//! NexusInbox — Reference Signer Daemon
//!
//! Holds the agent's Ed25519 signing key in memory and exposes a
//! Unix Domain Socket JSON-RPC interface for signing JWS assertions.
//!
//! Security design:
//!   - Private key NEVER leaves this process
//!   - Key at rest is encrypted with XChaCha20-Poly1305 (KEK from Argon2id passphrase)
//!   - UDS file mode 0600 — only the daemon UID can connect
//!   - Policy L1: rate-limits token signing requests per hour
//!
//! See docs/15_non_interactive_agent_access_design.md §4, §6, §7.

use aes_gcm::{Aes256Gcm, Nonce as AesNonce};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use chrono::Utc;
use clap::Parser;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{
    collections::HashMap,
    io::Write as IoWrite,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixListener,
};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

mod bridge;
mod bridge_audit_forwarder;

pub(crate) fn derive_did_from_verifying_key(verifying_key: &VerifyingKey) -> String {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut multicodec = Vec::with_capacity(34);
    multicodec.push(0xed);
    multicodec.push(0x01);
    multicodec.extend_from_slice(&verifying_key.to_bytes());

    let zeros = multicodec.iter().take_while(|&&b| b == 0).count();
    let mut input = multicodec.clone();
    let mut encoded = Vec::new();

    let mut start_at = zeros;
    while start_at < input.len() {
        let mut remainder: u32 = 0;
        for byte in input.iter_mut().skip(start_at) {
            let value = (remainder << 8) + *byte as u32;
            *byte = (value / 58) as u8;
            remainder = value % 58;
        }
        encoded.push(ALPHABET[remainder as usize] as char);
        while start_at < input.len() && input[start_at] == 0 {
            start_at += 1;
        }
    }

    encoded.extend(std::iter::repeat_n('1', zeros));
    encoded.reverse();
    format!("did:key:z{}", encoded.into_iter().collect::<String>())
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "nexusinbox-signer", about = "NexusInbox Signer Daemon")]
struct Cli {
    /// Path to the Unix Domain Socket
    #[arg(long, default_value = "/tmp/nexusinbox-signer.sock")]
    socket: PathBuf,

    /// Path to the key file (encrypted .key.enc or plaintext .key)
    #[arg(long, default_value = "signing.key.enc")]
    key_file: PathBuf,

    /// Optional X25519 encryption-key file. When set, the daemon can
    /// also fulfil `unwrap_content_key` RPC calls so Gateway / MCP
    /// adapters can decrypt inbound message bodies without ever
    /// holding the recipient's private key themselves.
    ///
    /// Shares the passphrase of `--key-file` (single prompt per boot).
    /// Absent ⇒ `unwrap_content_key` RPC is disabled and returns an
    /// error — signing-only deployments keep working unchanged.
    #[arg(long)]
    encryption_key_file: Option<PathBuf>,

    /// Generate a new key pair (interactive: prompts for passphrase).
    /// When paired with --encryption-key-file, also generates an X25519
    /// keypair sharing the same passphrase.
    #[arg(long)]
    generate: bool,

    /// Allow plaintext key file (INSECURE — for development only)
    #[arg(long)]
    unsafe_plaintext_key: bool,

    /// Agent ID (aid:ai:...)
    #[arg(long)]
    aid: Option<String>,

    /// Credential ID (UUID)
    #[arg(long)]
    credential_id: Option<String>,

    /// API base URL for token endpoint
    #[arg(long, default_value = "http://localhost:3001/api")]
    api_url: String,

    /// Comma-separated scope ceiling for JWS assertions this daemon
    /// will sign (e.g. `--allowed-scopes messages.read,messages.send`).
    /// Callers of `sign_assertion` may request a **subset** of this
    /// list; anything outside it is rejected. This is a local policy
    /// boundary — the API re-enforces its own scope cap per
    /// credential on the token-exchange side. Defaults to the Phase 1
    /// surface (`messages.read messages.send`) so existing daemons
    /// keep working unchanged after upgrade.
    #[arg(long, default_value = "messages.read,messages.send")]
    allowed_scopes: String,

    /// Maximum token sign requests per hour per credential (Policy L1)
    #[arg(long, default_value = "6")]
    max_signs_per_hour: u32,

    /// Allowed peer UID for SO_PEERCRED check (§4.3 IPC security).
    /// If set, only connections from this UID are accepted.
    /// Typically the UID of the Gateway process.
    #[arg(long)]
    allowed_uid: Option<u32>,

    // ------------------------------------------------------------
    // Bridged-restore HTTP listener (docs/22 Phase 3a).
    // ------------------------------------------------------------
    /// Enable the loopback HTTP listener so the Web UI can request
    /// on-demand `unwrap_content_key` operations. Off by default —
    /// Phase 3a explicitly ships behind a flag so legacy deployments
    /// remain signing-only.
    #[arg(long, default_value = "false")]
    bridge_enable: bool,

    /// TCP port for the bridge listener. Always binds to 127.0.0.1
    /// (enforced in the bridge module); cannot be exposed on a
    /// non-loopback interface.
    #[arg(long, default_value = "43417")]
    bridge_port: u16,

    /// Allowed `Origin:` header for bridge requests. Exact match, no
    /// wildcard. Defaults to the canonical production Web origin so
    /// local dev against `http://localhost:3000` needs an explicit
    /// override.
    #[arg(long, default_value = "https://app.nexusinbox.ai")]
    bridge_allowed_origin: String,

    /// Optional long-lived shared secret accepted in the
    /// `X-NexusInbox-Bridge` header alongside any Phase 3b pairing
    /// tokens. Read from `--bridge-token` or the
    /// `AGENT_INBOX_BRIDGE_TOKEN` env var. Leaving both unset puts
    /// the daemon in pairing-only mode — a short-lived pairing code
    /// is printed to stderr at startup and the Web UI trades it for
    /// a real bearer via `POST /v1/pair`. Phase 3a deployments that
    /// already set `AGENT_INBOX_BRIDGE_TOKEN` keep working unchanged.
    #[arg(long, env = "AGENT_INBOX_BRIDGE_TOKEN")]
    bridge_token: Option<String>,

    /// Policy L3 (docs/22 §4.1): max bridged decrypts per rolling
    /// day. Defaults to 50 — enough for a legit user restoring a
    /// few messages a day, tight enough to cap the blast radius of
    /// a leaked token.
    #[arg(long, default_value = "50")]
    bridge_decrypts_per_day: u32,

    /// Policy L3: max bridged decrypts per rolling minute. Stops
    /// burst exfiltration before the daily window even fills up.
    /// Default 3 matches docs/22 §4.1 recommendation.
    #[arg(long, default_value = "3")]
    bridge_decrypts_per_min: u32,

    /// Phase 3c.3 — when set, the daemon forwards every bridge
    /// audit event to `<api-url>/agent-audit-log/bridge` using a
    /// per-event JWS signed with the agent's credential. The local
    /// stderr JSON-Lines stream stays on regardless; this just
    /// adds central observability. Off by default because it
    /// opens an outbound HTTP connection — ops should opt in per
    /// deployment.
    #[arg(long, default_value = "false")]
    bridge_forward_audit: bool,
}

// ---------------------------------------------------------------------------
// Key management
// ---------------------------------------------------------------------------

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24; // XChaCha20-Poly1305 nonce

/// Encrypt a 32-byte signing key with a passphrase.
///
/// Format: salt (16B) || nonce (24B) || ciphertext (32B + 16B tag)
fn encrypt_key(signing_key: &[u8; 32], passphrase: &str) -> Vec<u8> {
    let salt: [u8; SALT_LEN] = rand::random();
    let kek = derive_kek(passphrase, &salt);

    let cipher = XChaCha20Poly1305::new_from_slice(&kek).expect("invalid key length");
    let nonce_bytes: [u8; NONCE_LEN] = rand::random();
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, signing_key.as_slice())
        .expect("encryption failed");

    let mut out = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    out
}

/// Decrypt a signing key from the encrypted file format.
fn decrypt_key(data: &[u8], passphrase: &str) -> Result<[u8; 32], String> {
    if data.len() < SALT_LEN + NONCE_LEN + 32 {
        return Err("encrypted key file too short".into());
    }

    let salt = &data[..SALT_LEN];
    let nonce_bytes = &data[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ciphertext = &data[SALT_LEN + NONCE_LEN..];

    let kek = derive_kek(passphrase, salt);
    let cipher =
        XChaCha20Poly1305::new_from_slice(&kek).map_err(|e| format!("cipher init: {e}"))?;
    let nonce = XNonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "decryption failed — wrong passphrase?".to_string())?;

    let key: [u8; 32] = plaintext
        .try_into()
        .map_err(|_| "decrypted key is not 32 bytes")?;
    Ok(key)
}

/// Derive a 32-byte KEK from passphrase + salt using Argon2id.
fn derive_kek(passphrase: &str, salt: &[u8]) -> [u8; 32] {
    use argon2::{Algorithm, Argon2, Params, Version};

    let params = Params::new(
        65536, // 64 MiB memory
        3,     // iterations
        1,     // parallelism
        Some(32),
    )
    .expect("invalid argon2 params");

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut output)
        .expect("argon2 hash failed");
    output
}

/// Read passphrase from stdin (no echo).
fn read_passphrase(prompt: &str) -> String {
    eprint!("{}", prompt);
    std::io::stderr().flush().ok();
    rpassword_fallback()
}

/// Simple passphrase reader (stdin, no echo if terminal).
fn rpassword_fallback() -> String {
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .expect("failed to read passphrase");
    line.trim().to_string()
}

/// Prompt for a passphrase (with confirmation) once. Returns None if
/// the caller asked for plaintext mode. Factored out so a single prompt
/// can gate both the Ed25519 signing key and an optional X25519
/// encryption key in one boot, keeping UX the same as the single-key
/// deployment.
fn prompt_new_passphrase(plaintext: bool) -> Option<String> {
    if plaintext {
        return None;
    }
    let pass = read_passphrase("Enter passphrase for key encryption: ");
    if pass.is_empty() {
        eprintln!("[ERROR] Passphrase cannot be empty.");
        std::process::exit(1);
    }
    let pass2 = read_passphrase("Confirm passphrase: ");
    if pass != pass2 {
        eprintln!("[ERROR] Passphrases do not match.");
        std::process::exit(1);
    }
    Some(pass)
}

/// Prompt for a passphrase once when unlocking. Returns None in
/// plaintext mode. Shared between Ed25519 + X25519 unlock paths so we
/// ask the operator only once per boot.
fn prompt_unlock_passphrase(plaintext: bool) -> Option<String> {
    if plaintext {
        return None;
    }
    Some(read_passphrase("Enter passphrase to unlock key: "))
}

/// Set POSIX 0600 on the just-written key file. No-op on non-unix.
fn chmod_key_file(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms).expect("failed to set key file permissions");
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// Persist a freshly-minted 32-byte key to disk, encrypted with
/// `passphrase` when present, or plaintext otherwise. Shared writer for
/// Ed25519 and X25519 key files — the encrypted format is identical.
fn save_key_bytes(path: &Path, key_bytes: &[u8; 32], passphrase: Option<&str>) {
    match passphrase {
        Some(pass) => {
            let encrypted = encrypt_key(key_bytes, pass);
            std::fs::write(path, &encrypted).expect("failed to write encrypted key file");
        }
        None => {
            eprintln!(
                "[WARN] Saving key in PLAINTEXT (--unsafe-plaintext-key). Do NOT use in production."
            );
            std::fs::write(path, key_bytes).expect("failed to write key file");
        }
    }
    chmod_key_file(path);
}

/// Read a 32-byte key from disk. Accepts either plaintext (32 raw
/// bytes) or the encrypted format and decrypts with `passphrase` when
/// provided.
fn load_key_bytes(path: &Path, passphrase: Option<&str>) -> [u8; 32] {
    let data = std::fs::read(path).unwrap_or_else(|e| {
        eprintln!("[ERROR] Cannot read key file {}: {}", path.display(), e);
        std::process::exit(1);
    });

    match passphrase {
        None => {
            if data.len() != 32 {
                eprintln!(
                    "[ERROR] Plaintext key file must be exactly 32 bytes ({}).",
                    path.display()
                );
                std::process::exit(1);
            }
            data.try_into().unwrap()
        }
        Some(pass) => match decrypt_key(&data, pass) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("[ERROR] {} ({})", e, path.display());
                std::process::exit(1);
            }
        },
    }
}

/// Generate a new Ed25519 keypair, encrypt it, and write to disk.
fn generate_and_save_key(path: &Path, passphrase: Option<&str>) -> SigningKey {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    save_key_bytes(path, &signing_key.to_bytes(), passphrase);

    let pub_b64 = URL_SAFE_NO_PAD.encode(verifying_key.to_bytes());
    eprintln!("[INFO] Ed25519 signing key generated.");
    eprintln!("[INFO] Public key (base64url): {}", pub_b64);
    eprintln!("[INFO] Key file: {}", path.display());

    signing_key
}

/// Load an Ed25519 signing key from disk.
fn load_key(path: &Path, passphrase: Option<&str>) -> SigningKey {
    let key_bytes = load_key_bytes(path, passphrase);
    SigningKey::from_bytes(&key_bytes)
}

/// Generate a new X25519 `StaticSecret`, encrypt it at rest, write to
/// disk, and return the in-memory secret. Used at boot when the
/// operator passed `--generate --encryption-key-file ...` so the daemon
/// can later fulfil `unwrap_content_key` RPCs.
fn generate_and_save_encryption_secret(path: &Path, passphrase: Option<&str>) -> StaticSecret {
    // Raw 32-byte seed ⇒ StaticSecret (clamping happens during DH).
    // Using `rand::random` keeps the RNG source identical to the
    // Ed25519 path above and avoids taking another crate.
    let raw: [u8; 32] = rand::random();
    let secret = StaticSecret::from(raw);
    let public = X25519PublicKey::from(&secret);
    save_key_bytes(path, &secret.to_bytes(), passphrase);

    let pub_b64 = URL_SAFE_NO_PAD.encode(public.as_bytes());
    eprintln!("[INFO] X25519 encryption key generated.");
    eprintln!("[INFO] Encryption public key (base64url): {}", pub_b64);
    eprintln!("[INFO] Encryption key file: {}", path.display());

    secret
}

/// Load an X25519 `StaticSecret` previously persisted by
/// `generate_and_save_encryption_secret`.
fn load_encryption_secret(path: &Path, passphrase: Option<&str>) -> StaticSecret {
    let key_bytes = load_key_bytes(path, passphrase);
    StaticSecret::from(key_bytes)
}

// ---------------------------------------------------------------------------
// JWS signing
// ---------------------------------------------------------------------------

/// Build and sign a JWS compact serialization (header.payload.signature).
fn sign_jws(
    signing_key: &SigningKey,
    aid: &str,
    credential_id: &str,
    audience: &str,
    scopes: &str,
) -> String {
    // Header
    let header = serde_json::json!({
        "alg": "EdDSA",
        "typ": "JWT"
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());

    // Payload
    let now = Utc::now().timestamp();
    let jti = uuid::Uuid::new_v4().to_string();
    let payload = serde_json::json!({
        "iss": aid,
        "sub": credential_id,
        "aud": audience,
        "jti": jti,
        "iat": now,
        "exp": now + 60,
        "scope": scopes,
    });
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());

    // Sign
    let signing_input = format!("{}.{}", header_b64, payload_b64);
    let signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    format!("{}.{}.{}", header_b64, payload_b64, sig_b64)
}

// ---------------------------------------------------------------------------
// Policy L1: Rate limiting
// ---------------------------------------------------------------------------

struct RateLimiter {
    /// credential_id -> list of timestamps (within the current window)
    windows: HashMap<String, Vec<Instant>>,
    max_per_hour: u32,
}

impl RateLimiter {
    fn new(max_per_hour: u32) -> Self {
        Self {
            windows: HashMap::new(),
            max_per_hour,
        }
    }

    /// Check and record a signing request. Returns Ok(()) or Err with message.
    fn check(&mut self, credential_id: &str) -> Result<(), String> {
        let now = Instant::now();
        let window = std::time::Duration::from_secs(3600);

        let entries = self.windows.entry(credential_id.to_string()).or_default();

        // Prune old entries
        entries.retain(|t| now.duration_since(*t) < window);

        if entries.len() >= self.max_per_hour as usize {
            return Err(format!(
                "rate limit exceeded: {} sign requests per hour (max {})",
                entries.len(),
                self.max_per_hour
            ));
        }

        entries.push(now);
        Ok(())
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
// Daemon state
// ---------------------------------------------------------------------------

pub(crate) struct DaemonState {
    pub(crate) signing_key: SigningKey,
    pub(crate) verifying_key: VerifyingKey,
    /// Optional X25519 private key for `unwrap_content_key` RPC.
    /// `None` ⇒ daemon rejects unwrap calls (Phase 2.5 signing-only
    /// deployments). When `Some`, the secret never leaves this process
    /// — only the derived content_key plaintext does, over the UDS.
    pub(crate) encryption_secret: Option<StaticSecret>,
    pub(crate) aid: String,
    pub(crate) credential_id: String,
    api_url: String,
    /// Scope ceiling enforced by `handle_sign_assertion`. Caller-
    /// supplied `scopes` must be a subset of this list — otherwise
    /// the request is rejected before any signature is produced, so
    /// a compromised Gateway / MCP peer can't mint an assertion
    /// outside the credential's intended privilege.
    allowed_scopes: Vec<String>,
    rate_limiter: Mutex<RateLimiter>,
    start_time: Instant,
    /// If set, only accept UDS connections from this UID (SO_PEERCRED, §4.3).
    allowed_uid: Option<u32>,
}

#[derive(Deserialize)]
struct SignEnvelopeParams {
    sender_did: String,
    recipient_did: String,
    subject_encrypted: String,
    encrypted_content: String,
    encrypted_key: String,
    nonce: String,
}

fn build_envelope_signing_payload(params: &SignEnvelopeParams) -> String {
    format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        params.sender_did,
        params.recipient_did,
        params.subject_encrypted,
        params.encrypted_content,
        params.encrypted_key,
        params.nonce
    )
}

// ---------------------------------------------------------------------------
// RPC handler
// ---------------------------------------------------------------------------

fn handle_rpc(state: &DaemonState, req: &RpcRequest) -> RpcResponse {
    match req.method.as_str() {
        "sign_assertion" => handle_sign_assertion(state, req),
        "sign_envelope" => handle_sign_envelope(state, req),
        "get_public_key" => handle_get_public_key(state, req),
        "unwrap_content_key" => handle_unwrap_content_key(state, req),
        "wrap_content_key" => handle_wrap_content_key(state, req),
        "status" => handle_status(state, req),
        _ => RpcResponse::error(
            req.id.clone(),
            -32601,
            format!("method '{}' not found", req.method),
        ),
    }
}

// ---------------------------------------------------------------------------
// Phase 2.5: unwrap_content_key
// ---------------------------------------------------------------------------
//
// Matches apps/web/lib/crypto/keywrap.ts. The wire format is:
//
//   x25519v1:<ephemeral_pub_b64url>:<salt_b64url>:<iv_b64url>:<ciphertext_b64url>
//
// ECDH(static_secret, ephemeral_pub) → shared_secret
// HKDF-SHA256(shared_secret, salt, info = "nexusinbox/x25519-wrap/v1")
//   → 32-byte AES-256 wrap key
// AES-GCM-256(iv, ciphertext) → content_key (UTF-8 string)
//
// The content_key is a JWK-ish base64url string the recipient then
// feeds back into `decryptText` to decrypt the message body itself.

const WRAP_PREFIX: &str = "x25519v1:";
const WRAP_HKDF_INFO: &[u8] = b"nexusinbox/x25519-wrap/v1";
const WRAP_IV_LEN: usize = 12;
const WRAP_SALT_LEN: usize = 16;
const X25519_KEY_LEN: usize = 32;

#[derive(Deserialize)]
struct UnwrapContentKeyParams {
    /// Full `x25519v1:...` wrapped key string as produced by the
    /// web-side `wrapContentKeyForRecipient`.
    encrypted_key: String,
}

fn decode_b64url_field(field: &str, name: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(field)
        .map_err(|e| format!("invalid base64url in {name}: {e}"))
}

pub(crate) fn unwrap_content_key(
    secret: &StaticSecret,
    wrapped_key: &str,
) -> Result<String, String> {
    let rest = wrapped_key
        .strip_prefix(WRAP_PREFIX)
        .ok_or_else(|| "unsupported wrapped key format (expected x25519v1:)".to_string())?;

    let parts: Vec<&str> = rest.split(':').collect();
    if parts.len() != 4 {
        return Err(format!(
            "invalid wrapped key format (expected 4 colon-separated fields, got {})",
            parts.len()
        ));
    }

    let ephemeral_pub_bytes = decode_b64url_field(parts[0], "ephemeral_public_key")?;
    let salt = decode_b64url_field(parts[1], "salt")?;
    let iv = decode_b64url_field(parts[2], "iv")?;
    let ciphertext = decode_b64url_field(parts[3], "ciphertext")?;

    if ephemeral_pub_bytes.len() != X25519_KEY_LEN {
        return Err("ephemeral public key must be 32 bytes".into());
    }
    if salt.len() != WRAP_SALT_LEN {
        return Err(format!("salt must be {} bytes", WRAP_SALT_LEN));
    }
    if iv.len() != WRAP_IV_LEN {
        return Err(format!("iv must be {} bytes (AES-GCM nonce)", WRAP_IV_LEN));
    }

    let mut pub_arr = [0u8; X25519_KEY_LEN];
    pub_arr.copy_from_slice(&ephemeral_pub_bytes);
    let ephemeral_pub = X25519PublicKey::from(pub_arr);

    let shared = secret.diffie_hellman(&ephemeral_pub);

    // HKDF-SHA256(shared_secret, salt, info = "nexusinbox/x25519-wrap/v1")
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes());
    let mut wrap_key = [0u8; 32];
    hk.expand(WRAP_HKDF_INFO, &mut wrap_key)
        .map_err(|e| format!("HKDF expand failed: {e}"))?;

    let cipher =
        Aes256Gcm::new_from_slice(&wrap_key).map_err(|e| format!("AES-GCM init failed: {e}"))?;
    let nonce = AesNonce::from_slice(&iv);
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| "AES-GCM decryption failed — wrong recipient key?".to_string())?;

    String::from_utf8(plaintext).map_err(|e| format!("content_key is not valid UTF-8: {e}"))
}

/// Phase 4.4c+ (docs/25c-a §2.2). Produces a `x25519v1:...` wrapped
/// content key the same way the TS-side `wrapContentKeyForRecipient`
/// does — ephemeral ECDH → HKDF-SHA256 → AES-256-GCM. Only the
/// daemon does this so Isolated mode executors can encrypt outgoing replies
/// without the Gateway ever touching the wrap key material directly.
#[derive(Deserialize)]
struct WrapContentKeyParams {
    /// Base64url-encoded recipient X25519 public key (32 bytes).
    recipient_encryption_pub: String,
    /// The symmetric content key to wrap. UTF-8 string (typically
    /// JWK-shaped base64url) — wire-compatible with
    /// `unwrap_content_key` which expects a UTF-8 plaintext.
    content_key: String,
}

pub(crate) fn wrap_content_key(
    recipient_pub_b64: &str,
    content_key: &str,
) -> Result<String, String> {
    let recipient_pub_bytes = decode_b64url_field(recipient_pub_b64, "recipient_encryption_pub")?;
    if recipient_pub_bytes.len() != X25519_KEY_LEN {
        return Err("recipient_encryption_pub must be 32 bytes".into());
    }
    let mut pub_arr = [0u8; X25519_KEY_LEN];
    pub_arr.copy_from_slice(&recipient_pub_bytes);
    let recipient_pub = X25519PublicKey::from(pub_arr);

    let ephemeral_raw: [u8; 32] = rand::random();
    let ephemeral_secret = StaticSecret::from(ephemeral_raw);
    let ephemeral_pub = X25519PublicKey::from(&ephemeral_secret);

    let shared = ephemeral_secret.diffie_hellman(&recipient_pub);
    let salt: [u8; WRAP_SALT_LEN] = rand::random();
    let iv: [u8; WRAP_IV_LEN] = rand::random();

    let hk = Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes());
    let mut wrap_key = [0u8; 32];
    hk.expand(WRAP_HKDF_INFO, &mut wrap_key)
        .map_err(|e| format!("HKDF expand failed: {e}"))?;

    let cipher =
        Aes256Gcm::new_from_slice(&wrap_key).map_err(|e| format!("AES-GCM init failed: {e}"))?;
    let nonce = AesNonce::from_slice(&iv);
    let ciphertext = cipher
        .encrypt(nonce, content_key.as_bytes())
        .map_err(|e| format!("AES-GCM encryption failed: {e}"))?;

    Ok(format!(
        "{prefix}{eph}:{salt}:{iv}:{ct}",
        prefix = WRAP_PREFIX,
        eph = URL_SAFE_NO_PAD.encode(ephemeral_pub.as_bytes()),
        salt = URL_SAFE_NO_PAD.encode(salt),
        iv = URL_SAFE_NO_PAD.encode(iv),
        ct = URL_SAFE_NO_PAD.encode(&ciphertext),
    ))
}

fn handle_wrap_content_key(_state: &DaemonState, req: &RpcRequest) -> RpcResponse {
    // Unlike unwrap, this doesn't need the daemon's own private key —
    // the ephemeral ECDH peer is generated locally on every call.
    // We still route it through the daemon (rather than the gateway
    // doing it directly) so all wrap/unwrap format decisions live in
    // one place and the TS/Rust wire format stays synchronised.
    let params: WrapContentKeyParams = match serde_json::from_value(req.params.clone()) {
        Ok(p) => p,
        Err(e) => {
            return RpcResponse::error(
                req.id.clone(),
                -32602,
                format!("invalid wrap_content_key params: {e}"),
            );
        }
    };

    match wrap_content_key(&params.recipient_encryption_pub, &params.content_key) {
        Ok(wrapped) => RpcResponse::success(
            req.id.clone(),
            serde_json::json!({ "wrapped_key": wrapped }),
        ),
        Err(msg) => RpcResponse::error(req.id.clone(), -32000, msg),
    }
}

fn handle_unwrap_content_key(state: &DaemonState, req: &RpcRequest) -> RpcResponse {
    let Some(secret) = state.encryption_secret.as_ref() else {
        return RpcResponse::error(
            req.id.clone(),
            -32000,
            "unwrap_content_key disabled: no --encryption-key-file configured".into(),
        );
    };

    let params: UnwrapContentKeyParams = match serde_json::from_value(req.params.clone()) {
        Ok(p) => p,
        Err(e) => {
            return RpcResponse::error(
                req.id.clone(),
                -32602,
                format!("invalid unwrap_content_key params: {e}"),
            )
        }
    };

    match unwrap_content_key(secret, &params.encrypted_key) {
        Ok(content_key) => RpcResponse::success(
            req.id.clone(),
            serde_json::json!({
                "content_key": content_key,
            }),
        ),
        Err(msg) => RpcResponse::error(req.id.clone(), -32000, msg),
    }
}

fn handle_sign_envelope(state: &DaemonState, req: &RpcRequest) -> RpcResponse {
    let params: SignEnvelopeParams = match serde_json::from_value(req.params.clone()) {
        Ok(params) => params,
        Err(e) => {
            return RpcResponse::error(
                req.id.clone(),
                -32602,
                format!("invalid sign_envelope params: {}", e),
            )
        }
    };

    let current_did = derive_did_from_verifying_key(&state.verifying_key);
    if params.sender_did != current_did {
        return RpcResponse::error(
            req.id.clone(),
            -32602,
            "sender_did does not match current signer DID".into(),
        );
    }

    let payload = build_envelope_signing_payload(&params);
    let signature = state.signing_key.sign(payload.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    RpcResponse::success(
        req.id.clone(),
        serde_json::json!({
            "sender_did": current_did,
            "signature": signature_b64,
        }),
    )
}

fn handle_sign_assertion(state: &DaemonState, req: &RpcRequest) -> RpcResponse {
    // Audience is ALWAYS the daemon's configured token endpoint.
    // Caller overrides used to be honoured — that let any UDS peer
    // (compromised Gateway, malicious MCP extension) trick the
    // daemon into signing assertions targeting a third-party URL
    // for phishing, and also bypassed the API's aud check by
    // matching whatever aud the daemon decided to stamp. Killing
    // the override closes both.
    let audience = format!("{}/agent-auth/token", state.api_url.trim_end_matches('/'));

    // Scopes are clamped to the daemon's configured ceiling. A
    // caller may request a narrower subset (down-select is useful
    // so a single credential can mint least-privilege tokens per
    // task), but anything outside the ceiling is a hard reject —
    // never silently broadened, never falling back to "all of the
    // caller's wish list". Absent param ⇒ mint the full ceiling.
    let requested: Vec<String> = match req.params.get("scopes") {
        None | Some(serde_json::Value::Null) => state.allowed_scopes.clone(),
        Some(serde_json::Value::String(s)) => s.split_whitespace().map(String::from).collect(),
        Some(other) => {
            return RpcResponse::error(
                req.id.clone(),
                -32602,
                format!("scopes must be a space-separated string, got {}", other),
            );
        }
    };
    for scope in &requested {
        if !state.allowed_scopes.iter().any(|a| a == scope) {
            return RpcResponse::error(
                req.id.clone(),
                -32000,
                format!(
                    "scope '{scope}' is not permitted by this daemon's --allowed-scopes policy"
                ),
            );
        }
    }
    let scopes_line = requested.join(" ");

    // Policy L1: rate limit check
    {
        let mut limiter = state.rate_limiter.lock().unwrap();
        if let Err(msg) = limiter.check(&state.credential_id) {
            return RpcResponse::error(req.id.clone(), -32000, msg);
        }
    }

    let jws = sign_jws(
        &state.signing_key,
        &state.aid,
        &state.credential_id,
        &audience,
        &scopes_line,
    );

    RpcResponse::success(
        req.id.clone(),
        serde_json::json!({
            "assertion": jws,
            "aid": state.aid,
            "credential_id": state.credential_id,
        }),
    )
}

fn handle_get_public_key(state: &DaemonState, req: &RpcRequest) -> RpcResponse {
    let pub_b64 = URL_SAFE_NO_PAD.encode(state.verifying_key.to_bytes());
    let did = derive_did_from_verifying_key(&state.verifying_key);
    // When the daemon also holds an X25519 key, expose its public
    // component so the Gateway can publish / rotate it via the
    // credential-activation API without ever seeing the private half.
    let encryption_public_key = state.encryption_secret.as_ref().map(|secret| {
        let pk = X25519PublicKey::from(secret);
        URL_SAFE_NO_PAD.encode(pk.as_bytes())
    });
    let mut body = serde_json::json!({
        "public_key": pub_b64,
        "aid": state.aid,
        "did": did,
    });
    if let Some(enc) = encryption_public_key {
        body.as_object_mut().unwrap().insert(
            "encryption_public_key".into(),
            serde_json::Value::String(enc),
        );
    }
    RpcResponse::success(req.id.clone(), body)
}

fn handle_status(state: &DaemonState, req: &RpcRequest) -> RpcResponse {
    let uptime_secs = state.start_time.elapsed().as_secs();
    let pub_b64 = URL_SAFE_NO_PAD.encode(state.verifying_key.to_bytes());
    let did = derive_did_from_verifying_key(&state.verifying_key);

    let rate_info = {
        let limiter = state.rate_limiter.lock().unwrap();
        let count = limiter
            .windows
            .get(&state.credential_id)
            .map(|v| v.len())
            .unwrap_or(0);
        serde_json::json!({
            "signs_this_hour": count,
            "max_per_hour": limiter.max_per_hour,
        })
    };

    RpcResponse::success(
        req.id.clone(),
        serde_json::json!({
            "daemon": "nexusinbox-signer",
            "version": env!("CARGO_PKG_VERSION"),
            "uptime_seconds": uptime_secs,
            "aid": state.aid,
            "did": did,
            "credential_id": state.credential_id,
            "public_key": pub_b64,
            "rate_limit": rate_info,
        }),
    )
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Key management — single passphrase prompt for both Ed25519 and
    // optional X25519 key files, so the operator doesn't have to type
    // it twice per boot.
    let passphrase: Option<String> = if cli.generate {
        prompt_new_passphrase(cli.unsafe_plaintext_key)
    } else if !cli.unsafe_plaintext_key {
        prompt_unlock_passphrase(false)
    } else {
        None
    };

    let signing_key = if cli.generate {
        generate_and_save_key(&cli.key_file, passphrase.as_deref())
    } else {
        if !cli.key_file.exists() {
            eprintln!(
                "[ERROR] Key file not found: {}. Use --generate to create one.",
                cli.key_file.display()
            );
            std::process::exit(1);
        }
        load_key(&cli.key_file, passphrase.as_deref())
    };

    let encryption_secret: Option<StaticSecret> = match cli.encryption_key_file.as_ref() {
        None => None,
        Some(enc_path) => {
            let secret = if cli.generate {
                generate_and_save_encryption_secret(enc_path, passphrase.as_deref())
            } else {
                if !enc_path.exists() {
                    eprintln!(
                        "[ERROR] Encryption key file not found: {}. Use --generate to create one.",
                        enc_path.display()
                    );
                    std::process::exit(1);
                }
                load_encryption_secret(enc_path, passphrase.as_deref())
            };
            Some(secret)
        }
    };

    let verifying_key = signing_key.verifying_key();
    let pub_b64 = URL_SAFE_NO_PAD.encode(verifying_key.to_bytes());

    let aid = cli.aid.unwrap_or_else(|| {
        eprintln!("[WARN] No --aid specified. Using placeholder.");
        "aid:ai:PLACEHOLDER".to_string()
    });

    let credential_id = cli.credential_id.unwrap_or_else(|| {
        eprintln!("[WARN] No --credential-id specified. Using placeholder.");
        uuid::Uuid::new_v4().to_string()
    });

    eprintln!("[INFO] NexusInbox Signer Daemon starting");
    eprintln!("[INFO]   AID:           {}", aid);
    eprintln!("[INFO]   Credential ID: {}", credential_id);
    eprintln!("[INFO]   Public key:    {}", pub_b64);
    if let Some(secret) = encryption_secret.as_ref() {
        let enc_pub = URL_SAFE_NO_PAD.encode(X25519PublicKey::from(secret).as_bytes());
        eprintln!("[INFO]   Enc pubkey:    {}", enc_pub);
        eprintln!("[INFO]   unwrap_content_key RPC: ENABLED");
    } else {
        eprintln!("[INFO]   unwrap_content_key RPC: disabled (no --encryption-key-file)");
    }
    eprintln!("[INFO]   Socket:        {}", cli.socket.display());
    eprintln!(
        "[INFO]   Rate limit:    {} signs/hour",
        cli.max_signs_per_hour
    );

    // Parse the comma-separated scope list into the ceiling this
    // daemon will enforce on sign_assertion calls. Empty tokens
    // from stray commas are dropped so `--allowed-scopes
    // "messages.read,,messages.send"` still DWIMs.
    let allowed_scopes: Vec<String> = cli
        .allowed_scopes
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if allowed_scopes.is_empty() {
        eprintln!("[FATAL] --allowed-scopes must list at least one scope (got empty after trim)");
        std::process::exit(2);
    }
    eprintln!("[INFO]   Allowed scopes: {}", allowed_scopes.join(", "));

    let state = Arc::new(DaemonState {
        signing_key,
        verifying_key,
        encryption_secret,
        aid,
        credential_id,
        api_url: cli.api_url.clone(),
        allowed_scopes,
        rate_limiter: Mutex::new(RateLimiter::new(cli.max_signs_per_hour)),
        start_time: Instant::now(),
        allowed_uid: cli.allowed_uid,
    });

    // Remove stale socket file if it exists
    if cli.socket.exists() {
        std::fs::remove_file(&cli.socket).ok();
    }

    // Ensure parent directory exists
    if let Some(parent) = cli.socket.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let listener = UnixListener::bind(&cli.socket).unwrap_or_else(|e| {
        eprintln!("[ERROR] Failed to bind UDS {}: {}", cli.socket.display(), e);
        std::process::exit(1);
    });

    // Set socket permissions to 0600
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&cli.socket, perms).ok();
    }

    eprintln!("[INFO] Listening on {}", cli.socket.display());

    // Handle SIGTERM/SIGINT gracefully
    let socket_path = cli.socket.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        eprintln!("\n[INFO] Shutting down...");
        std::fs::remove_file(&socket_path).ok();
        std::process::exit(0);
    });

    if let Some(uid) = state.allowed_uid {
        eprintln!("[INFO]   Allowed UID:   {}", uid);
    }

    // Spin up the Phase 3a bridge listener if the operator opted in.
    // Runs as its own Tokio task alongside the UDS accept loop below;
    // bridge failures are logged to stderr but don't kill the signing
    // RPC path.
    if cli.bridge_enable {
        if state.encryption_secret.is_none() {
            eprintln!(
                "[ERROR] --bridge-enable requires --encryption-key-file \
                 (bridge unwrap has nothing to unwrap without it)."
            );
            std::process::exit(1);
        }
        let bridge_addr: std::net::SocketAddr = std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            cli.bridge_port,
        );
        let bridge_state = Arc::clone(&state);
        // Phase 3b: --bridge-token is now optional. When absent, the
        // daemon uses the pairing-code flow exclusively (printed to
        // stderr on startup). When present, it is kept as a backward-
        // compat shared secret alongside paired tokens so Phase 3a
        // operators don't have to change anything.
        let mut bridge_config = bridge::BridgeConfig::with_shared_secret(
            cli.bridge_token.clone(),
            cli.bridge_allowed_origin.clone(),
        );
        // CLI flags override the baked-in defaults from
        // `with_shared_secret`. Validated minimally (non-zero) so a
        // `0` value doesn't make the daemon trivially brick every
        // unwrap.
        if cli.bridge_decrypts_per_day == 0 || cli.bridge_decrypts_per_min == 0 {
            eprintln!(
                "[ERROR] --bridge-decrypts-per-day and --bridge-decrypts-per-min must be > 0."
            );
            std::process::exit(1);
        }
        bridge_config.decrypts_per_day_max = cli.bridge_decrypts_per_day;
        bridge_config.decrypts_per_min_max = cli.bridge_decrypts_per_min;
        eprintln!(
            "[INFO]   Bridge rate:   {} / day, {} / minute (Policy L3)",
            bridge_config.decrypts_per_day_max, bridge_config.decrypts_per_min_max
        );
        if cli.bridge_token.is_some() {
            eprintln!(
                "[INFO]   Bridge:        ENABLED on {} (origin {}) + shared-secret compat",
                bridge_addr, cli.bridge_allowed_origin
            );
        } else {
            eprintln!(
                "[INFO]   Bridge:        ENABLED on {} (origin {}); pairing-only mode",
                bridge_addr, cli.bridge_allowed_origin
            );
        }

        // Phase 3c.3 audit forwarder. Spawned only when the operator
        // opts in AND we actually have the credential / api-url
        // needed to authenticate the ingest JWS. The stderr sink
        // keeps running regardless, so "forwarder off" is still a
        // fully-audited deployment.
        let audit_tee = if cli.bridge_forward_audit {
            let fwd_signing = bridge_state.signing_key.clone();
            let tx = bridge_audit_forwarder::spawn(bridge_audit_forwarder::ForwarderConfig {
                api_base_url: cli.api_url.clone(),
                aid: bridge_state.aid.clone(),
                credential_id: bridge_state.credential_id.clone(),
                signing_key: fwd_signing,
            });
            eprintln!(
                "[INFO]   Bridge audit:  forwarding to {} (stderr stays on)",
                cli.api_url
            );
            Some(tx)
        } else {
            eprintln!(
                "[INFO]   Bridge audit:  stderr only (pass --bridge-forward-audit to tee to API)"
            );
            None
        };

        tokio::spawn(async move {
            if let Err(e) =
                bridge::run_bridge(bridge_state, bridge_config, bridge_addr, audit_tee).await
            {
                eprintln!("[ERROR] Bridge listener exited: {e}");
            }
        });
    } else {
        eprintln!("[INFO]   Bridge:        disabled (pass --bridge-enable to turn on)");
    }

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                // SO_PEERCRED check (§4.3 IPC security)
                #[cfg(unix)]
                if let Some(allowed_uid) = state.allowed_uid {
                    match stream.peer_cred() {
                        Ok(cred) => {
                            let peer_uid = cred.uid();
                            // Also allow connections from root (uid 0) and
                            // the daemon's own uid for testing.
                            let my_uid = unsafe { libc::getuid() };
                            if peer_uid != allowed_uid && peer_uid != 0 && peer_uid != my_uid {
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

async fn handle_connection(state: Arc<DaemonState>, stream: tokio::net::UnixStream) {
    let (reader, mut writer) = stream.into_split();
    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();

    loop {
        line.clear();
        match buf_reader.read_line(&mut line).await {
            Ok(0) => break, // EOF
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                let response = match serde_json::from_str::<RpcRequest>(trimmed) {
                    Ok(req) => handle_rpc(&state, &req),
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
    use ed25519_dalek::Verifier;

    #[test]
    fn test_encrypt_decrypt_key() {
        let key = SigningKey::generate(&mut OsRng);
        let passphrase = "test-passphrase-123";

        let encrypted = encrypt_key(&key.to_bytes(), passphrase);
        let decrypted = decrypt_key(&encrypted, passphrase).unwrap();

        assert_eq!(key.to_bytes(), decrypted);
    }

    #[test]
    fn test_decrypt_wrong_passphrase() {
        let key = SigningKey::generate(&mut OsRng);
        let encrypted = encrypt_key(&key.to_bytes(), "correct");
        let result = decrypt_key(&encrypted, "wrong");
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_jws_format() {
        let key = SigningKey::generate(&mut OsRng);
        let jws = sign_jws(
            &key,
            "aid:ai:01TEST",
            "cred-123",
            "https://api.test/agent-auth/token",
            "messages.read messages.send",
        );

        let parts: Vec<&str> = jws.split('.').collect();
        assert_eq!(parts.len(), 3, "JWS must have 3 parts");

        // Verify header
        let header_json = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_json).unwrap();
        assert_eq!(header["alg"], "EdDSA");

        // Verify payload
        let payload_json = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_json).unwrap();
        assert_eq!(payload["iss"], "aid:ai:01TEST");
        assert_eq!(payload["sub"], "cred-123");
        assert_eq!(payload["scope"], "messages.read messages.send");

        // Verify signature
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap());
        key.verifying_key()
            .verify(signing_input.as_bytes(), &sig)
            .expect("signature verification failed");
    }

    #[test]
    fn test_rate_limiter() {
        let mut limiter = RateLimiter::new(3);
        assert!(limiter.check("cred-1").is_ok());
        assert!(limiter.check("cred-1").is_ok());
        assert!(limiter.check("cred-1").is_ok());
        assert!(limiter.check("cred-1").is_err()); // 4th should fail

        // Different credential should be independent
        assert!(limiter.check("cred-2").is_ok());
    }

    fn sign_assertion_test_state() -> DaemonState {
        let key = SigningKey::generate(&mut OsRng);
        let vk = key.verifying_key();
        DaemonState {
            signing_key: key,
            verifying_key: vk,
            aid: "aid:ai:01TEST".into(),
            credential_id: "cred-test".into(),
            api_url: "http://localhost:3001/api".into(),
            rate_limiter: Mutex::new(RateLimiter::new(10)),
            start_time: Instant::now(),
            encryption_secret: None,
            allowed_scopes: vec!["messages.read".to_string(), "messages.send".to_string()],
            allowed_uid: None,
        }
    }

    fn decode_assertion_payload(assertion: &str) -> serde_json::Value {
        let parts: Vec<&str> = assertion.split('.').collect();
        let payload_b64 = parts[1];
        let bytes = URL_SAFE_NO_PAD.decode(payload_b64).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[test]
    fn test_rpc_sign_assertion() {
        let state = sign_assertion_test_state();
        let req = RpcRequest {
            id: serde_json::json!(1),
            method: "sign_assertion".into(),
            params: serde_json::json!({}),
        };

        let resp = handle_rpc(&state, &req);
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert!(result["assertion"].as_str().unwrap().contains('.'));
    }

    #[test]
    fn sign_assertion_audience_is_hardcoded_even_when_caller_supplies_one() {
        // Phase: hardening (docs/22 fixup). Caller tries to override
        // audience — daemon must ignore and always sign for its own
        // configured api_url + /agent-auth/token. This defeats a
        // caller who wants to get an assertion aimed at a
        // third-party token endpoint for phishing or cross-endpoint
        // replay.
        let state = sign_assertion_test_state();
        let req = RpcRequest {
            id: serde_json::json!(1),
            method: "sign_assertion".into(),
            params: serde_json::json!({
                "audience": "https://evil.attacker.example/token",
            }),
        };
        let resp = handle_rpc(&state, &req);
        assert!(
            resp.error.is_none(),
            "override should be ignored, not rejected"
        );
        let jws = resp.result.unwrap()["assertion"]
            .as_str()
            .unwrap()
            .to_string();
        let payload = decode_assertion_payload(&jws);
        assert_eq!(
            payload["aud"].as_str().unwrap(),
            "http://localhost:3001/api/agent-auth/token",
            "aud must follow state.api_url, not caller-supplied value",
        );
    }

    #[test]
    fn sign_assertion_rejects_scopes_outside_allowed_ceiling() {
        // Caller asks for an out-of-ceiling scope — hard reject.
        // The daemon is the local policy boundary here; the API
        // also re-enforces, but we must not emit a signed JWS at
        // all for forbidden scope combinations.
        let state = sign_assertion_test_state();
        let req = RpcRequest {
            id: serde_json::json!(1),
            method: "sign_assertion".into(),
            params: serde_json::json!({
                "scopes": "messages.send admin",
            }),
        };
        let resp = handle_rpc(&state, &req);
        assert!(resp.error.is_some(), "admin scope must be rejected");
        let msg = resp.error.unwrap().message;
        assert!(
            msg.contains("admin"),
            "error message should name the forbidden scope, got {msg:?}",
        );
    }

    #[test]
    fn sign_assertion_down_selects_scopes_when_subset_of_ceiling() {
        // Caller asks for a strict subset ("messages.read" when
        // ceiling is "messages.read messages.send"). Daemon should
        // sign with exactly that subset so tokens minted downstream
        // can be least-privilege per task.
        let state = sign_assertion_test_state();
        let req = RpcRequest {
            id: serde_json::json!(1),
            method: "sign_assertion".into(),
            params: serde_json::json!({
                "scopes": "messages.read",
            }),
        };
        let resp = handle_rpc(&state, &req);
        assert!(resp.error.is_none());
        let jws = resp.result.unwrap()["assertion"]
            .as_str()
            .unwrap()
            .to_string();
        let payload = decode_assertion_payload(&jws);
        assert_eq!(payload["scope"].as_str().unwrap(), "messages.read");
    }

    #[test]
    fn sign_assertion_default_scope_is_the_full_ceiling() {
        // Caller supplies no `scopes` — daemon mints the full
        // ceiling. Used by legacy callers that haven't been
        // updated to down-select.
        let state = sign_assertion_test_state();
        let req = RpcRequest {
            id: serde_json::json!(1),
            method: "sign_assertion".into(),
            params: serde_json::json!({}),
        };
        let resp = handle_rpc(&state, &req);
        assert!(resp.error.is_none());
        let jws = resp.result.unwrap()["assertion"]
            .as_str()
            .unwrap()
            .to_string();
        let payload = decode_assertion_payload(&jws);
        assert_eq!(
            payload["scope"].as_str().unwrap(),
            "messages.read messages.send",
        );
    }

    #[test]
    fn test_rpc_get_public_key() {
        let key = SigningKey::generate(&mut OsRng);
        let vk = key.verifying_key();
        let state = DaemonState {
            signing_key: key,
            verifying_key: vk,
            aid: "aid:ai:01TEST".into(),
            credential_id: "cred-test".into(),
            api_url: "http://localhost:3001/api".into(),
            rate_limiter: Mutex::new(RateLimiter::new(10)),
            start_time: Instant::now(),
            encryption_secret: None,
            allowed_scopes: vec!["messages.read".to_string(), "messages.send".to_string()],
            allowed_uid: None,
        };

        let req = RpcRequest {
            id: serde_json::json!(1),
            method: "get_public_key".into(),
            params: serde_json::json!({}),
        };

        let resp = handle_rpc(&state, &req);
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        let pk = result["public_key"].as_str().unwrap().to_string();
        let decoded = URL_SAFE_NO_PAD.decode(&pk).unwrap();
        assert_eq!(decoded.len(), 32);
        let did = result["did"].as_str().unwrap().to_string();
        assert!(did.starts_with("did:key:z"));
    }

    #[test]
    fn test_rpc_sign_envelope() {
        let key = SigningKey::generate(&mut OsRng);
        let vk = key.verifying_key();
        let sender_did = derive_did_from_verifying_key(&vk);
        let state = DaemonState {
            signing_key: key,
            verifying_key: vk,
            aid: "aid:ai:01TEST".into(),
            credential_id: "cred-test".into(),
            api_url: "http://localhost:3001/api".into(),
            rate_limiter: Mutex::new(RateLimiter::new(10)),
            start_time: Instant::now(),
            encryption_secret: None,
            allowed_scopes: vec!["messages.read".to_string(), "messages.send".to_string()],
            allowed_uid: None,
        };

        let req = RpcRequest {
            id: serde_json::json!(1),
            method: "sign_envelope".into(),
            params: serde_json::json!({
                "sender_did": sender_did,
                "recipient_did": "did:key:zRecipient",
                "subject_encrypted": "subject",
                "encrypted_content": "content",
                "encrypted_key": "x25519v1:wrapped",
                "nonce": "nonce-123",
            }),
        };

        let resp = handle_rpc(&state, &req);
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(
            result["sender_did"],
            derive_did_from_verifying_key(&state.verifying_key)
        );
        let signature = result["signature"].as_str().unwrap();
        let bytes = URL_SAFE_NO_PAD.decode(signature).unwrap();
        assert_eq!(bytes.len(), 64);
    }

    #[test]
    fn test_rpc_status() {
        let key = SigningKey::generate(&mut OsRng);
        let vk = key.verifying_key();
        let state = DaemonState {
            signing_key: key,
            verifying_key: vk,
            aid: "aid:ai:01TEST".into(),
            credential_id: "cred-test".into(),
            api_url: "http://localhost:3001/api".into(),
            rate_limiter: Mutex::new(RateLimiter::new(10)),
            start_time: Instant::now(),
            encryption_secret: None,
            allowed_scopes: vec!["messages.read".to_string(), "messages.send".to_string()],
            allowed_uid: None,
        };

        let req = RpcRequest {
            id: serde_json::json!(1),
            method: "status".into(),
            params: serde_json::json!({}),
        };

        let resp = handle_rpc(&state, &req);
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(result["daemon"], "nexusinbox-signer");
        assert_eq!(result["aid"], "aid:ai:01TEST");
        assert!(result["did"].as_str().unwrap().starts_with("did:key:z"));
    }

    #[test]
    fn test_rpc_unknown_method() {
        let key = SigningKey::generate(&mut OsRng);
        let vk = key.verifying_key();
        let state = DaemonState {
            signing_key: key,
            verifying_key: vk,
            aid: "aid:ai:01TEST".into(),
            credential_id: "cred-test".into(),
            api_url: "http://localhost:3001/api".into(),
            rate_limiter: Mutex::new(RateLimiter::new(10)),
            start_time: Instant::now(),
            encryption_secret: None,
            allowed_scopes: vec!["messages.read".to_string(), "messages.send".to_string()],
            allowed_uid: None,
        };

        let req = RpcRequest {
            id: serde_json::json!(1),
            method: "unknown_method".into(),
            params: serde_json::json!({}),
        };

        let resp = handle_rpc(&state, &req);
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, -32601);
    }

    #[test]
    fn test_rate_limiter_per_credential_isolation() {
        let mut limiter = RateLimiter::new(2);

        assert!(limiter.check("cred-a").is_ok());
        assert!(limiter.check("cred-a").is_ok());
        assert!(limiter.check("cred-a").is_err());

        // cred-b is independent
        assert!(limiter.check("cred-b").is_ok());
        assert!(limiter.check("cred-b").is_ok());
        assert!(limiter.check("cred-b").is_err());
    }

    // -----------------------------------------------------------------
    // Phase 2.5: unwrap_content_key round-trip coverage
    // -----------------------------------------------------------------

    /// Emulate `apps/web/lib/crypto/keywrap.ts#wrapContentKeyForRecipient`
    /// from a test. Mirrors the exact wire format so the daemon-side
    /// `unwrap_content_key` has something concrete to decrypt.
    fn wrap_content_key_for_recipient(
        content_key: &str,
        recipient_pub: &X25519PublicKey,
    ) -> String {
        // Ephemeral X25519 secret.
        let ephemeral_raw: [u8; 32] = rand::random();
        let ephemeral_secret = StaticSecret::from(ephemeral_raw);
        let ephemeral_pub = X25519PublicKey::from(&ephemeral_secret);

        let shared = ephemeral_secret.diffie_hellman(recipient_pub);
        let salt: [u8; WRAP_SALT_LEN] = rand::random();
        let iv: [u8; WRAP_IV_LEN] = rand::random();

        let hk = Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes());
        let mut wrap_key = [0u8; 32];
        hk.expand(WRAP_HKDF_INFO, &mut wrap_key).unwrap();

        let cipher = Aes256Gcm::new_from_slice(&wrap_key).unwrap();
        let nonce = AesNonce::from_slice(&iv);
        let ciphertext = cipher
            .encrypt(nonce, content_key.as_bytes())
            .expect("wrap encrypt");

        format!(
            "{prefix}{eph}:{salt}:{iv}:{ct}",
            prefix = WRAP_PREFIX,
            eph = URL_SAFE_NO_PAD.encode(ephemeral_pub.as_bytes()),
            salt = URL_SAFE_NO_PAD.encode(salt),
            iv = URL_SAFE_NO_PAD.encode(iv),
            ct = URL_SAFE_NO_PAD.encode(&ciphertext),
        )
    }

    fn state_with_encryption(secret: StaticSecret) -> DaemonState {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        DaemonState {
            signing_key,
            verifying_key,
            encryption_secret: Some(secret),
            aid: "aid:ai:01TEST".into(),
            credential_id: "cred-test".into(),
            api_url: "http://localhost:3001/api".into(),
            allowed_scopes: vec!["messages.read".to_string(), "messages.send".to_string()],
            rate_limiter: Mutex::new(RateLimiter::new(10)),
            start_time: Instant::now(),
            allowed_uid: None,
        }
    }

    #[test]
    fn test_unwrap_content_key_roundtrip() {
        let raw: [u8; 32] = rand::random();
        let secret = StaticSecret::from(raw);
        let public = X25519PublicKey::from(&secret);

        let content_key = "test-content-key-42"; // arbitrary UTF-8 string
        let wrapped = wrap_content_key_for_recipient(content_key, &public);

        let recovered = unwrap_content_key(&secret, &wrapped).expect("unwrap");
        assert_eq!(recovered, content_key);
    }

    #[test]
    fn test_wrap_then_unwrap_roundtrip() {
        // Cover the production wrap function (exported for Isolated mode
        // executor callers) and its symmetry with unwrap.
        let raw: [u8; 32] = rand::random();
        let secret = StaticSecret::from(raw);
        let public = X25519PublicKey::from(&secret);
        let recipient_pub_b64 = URL_SAFE_NO_PAD.encode(public.as_bytes());

        let content_key = "another-test-content-key-xyz";
        let wrapped = wrap_content_key(&recipient_pub_b64, content_key).expect("wrap");

        let recovered = unwrap_content_key(&secret, &wrapped).expect("unwrap");
        assert_eq!(recovered, content_key);
    }

    #[test]
    fn test_wrap_content_key_rejects_bad_recipient_pub() {
        // Non-32-byte pubkey should fail cleanly rather than panic.
        let bogus_pub_b64 = URL_SAFE_NO_PAD.encode([0u8; 16]);
        let err = wrap_content_key(&bogus_pub_b64, "x").unwrap_err();
        assert!(err.contains("32 bytes"), "unexpected error: {err}");
    }

    #[test]
    fn test_rpc_wrap_content_key_success() {
        let raw: [u8; 32] = rand::random();
        let secret = StaticSecret::from(raw);
        let public = X25519PublicKey::from(&secret);
        let state = state_with_encryption(secret.clone());

        let recipient_pub_b64 = URL_SAFE_NO_PAD.encode(public.as_bytes());
        let req = RpcRequest {
            id: serde_json::json!(7),
            method: "wrap_content_key".into(),
            params: serde_json::json!({
                "recipient_encryption_pub": recipient_pub_b64,
                "content_key": "content-key-from-rpc",
            }),
        };
        let resp = handle_rpc(&state, &req);
        assert!(resp.error.is_none(), "expected success");
        let wrapped = resp.result.as_ref().unwrap()["wrapped_key"]
            .as_str()
            .unwrap()
            .to_string();
        let recovered = unwrap_content_key(&secret, &wrapped).expect("round-trip");
        assert_eq!(recovered, "content-key-from-rpc");
    }

    #[test]
    fn test_unwrap_content_key_rpc_success() {
        let raw: [u8; 32] = rand::random();
        let secret = StaticSecret::from(raw);
        let public = X25519PublicKey::from(&secret);
        let state = state_with_encryption(secret);

        let wrapped = wrap_content_key_for_recipient("jwk-style-opaque-string", &public);
        let req = RpcRequest {
            id: serde_json::json!(1),
            method: "unwrap_content_key".into(),
            params: serde_json::json!({ "encrypted_key": wrapped }),
        };

        let resp = handle_rpc(&state, &req);
        assert!(
            resp.error.is_none(),
            "expected success, got error code={:?}",
            resp.error.as_ref().map(|e| e.code),
        );
        let result = resp.result.unwrap();
        assert_eq!(result["content_key"], "jwk-style-opaque-string");
    }

    #[test]
    fn test_unwrap_content_key_rpc_disabled_when_no_secret() {
        // Same shape as the other RPC tests: encryption_secret = None.
        let key = SigningKey::generate(&mut OsRng);
        let vk = key.verifying_key();
        let state = DaemonState {
            signing_key: key,
            verifying_key: vk,
            encryption_secret: None,
            aid: "aid:ai:01TEST".into(),
            credential_id: "cred-test".into(),
            api_url: "http://localhost:3001/api".into(),
            allowed_scopes: vec!["messages.read".to_string(), "messages.send".to_string()],
            rate_limiter: Mutex::new(RateLimiter::new(10)),
            start_time: Instant::now(),
            allowed_uid: None,
        };

        let req = RpcRequest {
            id: serde_json::json!(1),
            method: "unwrap_content_key".into(),
            params: serde_json::json!({ "encrypted_key": "x25519v1:AA:BB:CC:DD" }),
        };

        let resp = handle_rpc(&state, &req);
        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32000);
        assert!(
            err.message.contains("disabled"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn test_unwrap_content_key_rpc_rejects_wrong_recipient() {
        // Wrap for recipient A, but hand the ciphertext to daemon B.
        let raw_a: [u8; 32] = rand::random();
        let secret_a = StaticSecret::from(raw_a);
        let public_a = X25519PublicKey::from(&secret_a);

        let raw_b: [u8; 32] = rand::random();
        let secret_b = StaticSecret::from(raw_b);

        let wrapped = wrap_content_key_for_recipient("secret-for-A", &public_a);
        let state = state_with_encryption(secret_b);

        let req = RpcRequest {
            id: serde_json::json!(1),
            method: "unwrap_content_key".into(),
            params: serde_json::json!({ "encrypted_key": wrapped }),
        };

        let resp = handle_rpc(&state, &req);
        assert!(resp.error.is_some());
        // Message explicitly calls out AES-GCM failure — don't leak
        // which stage fell over beyond that.
        let msg = resp.error.unwrap().message;
        assert!(msg.contains("AES-GCM"), "unexpected error: {msg}");
    }

    #[test]
    fn test_unwrap_content_key_rpc_rejects_malformed_input() {
        let raw: [u8; 32] = rand::random();
        let state = state_with_encryption(StaticSecret::from(raw));

        // Missing prefix.
        let req = RpcRequest {
            id: serde_json::json!(1),
            method: "unwrap_content_key".into(),
            params: serde_json::json!({ "encrypted_key": "not-an-envelope" }),
        };
        let resp = handle_rpc(&state, &req);
        assert!(resp.error.is_some());
        assert!(resp.error.unwrap().message.contains("unsupported"));

        // Too few colon-separated fields.
        let req = RpcRequest {
            id: serde_json::json!(2),
            method: "unwrap_content_key".into(),
            params: serde_json::json!({ "encrypted_key": "x25519v1:AA:BB" }),
        };
        let resp = handle_rpc(&state, &req);
        assert!(resp.error.is_some());
    }

    #[test]
    fn test_get_public_key_exposes_encryption_public_key_when_loaded() {
        let raw: [u8; 32] = rand::random();
        let secret = StaticSecret::from(raw);
        let expected_pub = URL_SAFE_NO_PAD.encode(X25519PublicKey::from(&secret).as_bytes());
        let state = state_with_encryption(secret);

        let req = RpcRequest {
            id: serde_json::json!(1),
            method: "get_public_key".into(),
            params: serde_json::json!({}),
        };

        let resp = handle_rpc(&state, &req);
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(
            result["encryption_public_key"].as_str().unwrap(),
            expected_pub
        );
    }
}
