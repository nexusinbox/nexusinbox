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

mod keychain;

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

    /// macOS: read the key passphrase from the login keychain item that
    /// --keychain-store saved under ACCOUNT, instead of from stdin. For
    /// starting at login without anyone typing it (docs/39).
    #[arg(long, value_name = "ACCOUNT")]
    passphrase_from_keychain: Option<String>,

    /// macOS: ask for the key passphrase once, check that it opens
    /// --key-file (and --encryption-key-file), save it in the login
    /// keychain under ACCOUNT, then exit. Only this program can read it
    /// back without macOS asking (docs/39).
    #[arg(long, value_name = "ACCOUNT")]
    keychain_store: Option<String>,

    /// macOS: delete the passphrase saved under ACCOUNT, then exit.
    #[arg(long, value_name = "ACCOUNT")]
    keychain_delete: Option<String>,

    /// Generate a new key pair (interactive: prompts for passphrase).
    /// When paired with --encryption-key-file, also generates an X25519
    /// keypair sharing the same passphrase.
    #[arg(long)]
    generate: bool,

    /// With --generate: replace an existing key file instead of refusing.
    /// The DID is derived from the signing key, so regenerating over a
    /// live key orphans every credential enrolled against it — overwrite
    /// is therefore opt-in.
    #[arg(long)]
    force: bool,

    /// Allow plaintext key file (INSECURE — for development only)
    #[arg(long)]
    unsafe_plaintext_key: bool,

    /// Agent ID (aid:ai:...)
    #[arg(long)]
    aid: Option<String>,

    /// Credential ID (UUID)
    #[arg(long)]
    credential_id: Option<String>,

    /// Enroll this daemon for a credential created in the web UI, then exit:
    /// generate the signing and encryption keys (passphrase-encrypted
    /// unless --unsafe-plaintext-key) and register their public halves with
    /// `POST {api-url}/agent-credentials/{credential-id}/activate`. The
    /// one-shot enrollment secret is read from AGENT_INBOX_ENROLLMENT_SECRET
    /// or asked for without echo — never taken from the command line, so it
    /// does not show in the process list or shell history.
    /// Needs --credential-id, and --dir (or --key-file and
    /// --encryption-key-file).
    #[arg(long)]
    enroll: bool,

    /// Connect this machine to an agent with the pairing code the web UI
    /// shows (docs/31), then exit: look the code up, generate both keys in
    /// a new directory under ~/.nexusinbox (or --dir), activate the
    /// credential and write `agent.env`. The directory is printed on
    /// stdout. Unlike an enrollment secret the code may be on the command
    /// line: it works once and expires 10 minutes after it was shown.
    #[arg(long, value_name = "CODE", conflicts_with = "enroll")]
    connect: Option<String>,

    /// With --enroll: keep everything for this agent in one directory
    /// (created with mode 0700 if missing): the two key files and
    /// `agent.env`, the settings `scripts/run_noninteractive_stack.sh start
    /// <dir>` reads, so starting never needs them spelled out again.
    #[arg(long)]
    dir: Option<PathBuf>,

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

/// Read passphrase from stdin (no echo). The prompt is shown only to
/// someone typing: when a script pipes the passphrase in (the stack
/// script's `connect` and `start`), a prompt after the fact would read as
/// a second question.
fn read_passphrase(prompt: &str) -> String {
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        eprint!("{}", prompt);
        std::io::stderr().flush().ok();
    }
    rpassword_fallback()
}

/// Passphrase reader. On a terminal, go through `rpassword` so the
/// passphrase is never echoed (shoulder-surfing, screen shares, terminal
/// scrollback). When stdin is piped — scripts, tests — there is no echo to
/// suppress and rpassword would try to open /dev/tty, so fall back to a
/// plain line read.
fn rpassword_fallback() -> String {
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        return rpassword::read_password()
            .expect("failed to read passphrase")
            .trim()
            .to_string();
    }
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

/// `--keychain-store`: the passphrase must open the key files before it is
/// saved, so a typo is caught now rather than at the next login.
fn run_keychain_store(cli: &Cli, account: &str) -> i32 {
    let pass = read_passphrase("Enter the passphrase of this agent's keys: ");
    if pass.is_empty() {
        eprintln!("[ERROR] No passphrase entered; nothing saved.");
        return 1;
    }
    let opens = |path: &Path| load_key_bytes_checked(path, &pass);
    if let Err(e) = opens(&cli.key_file) {
        eprintln!("[ERROR] {}: {e}", cli.key_file.display());
        return 1;
    }
    if let Some(enc) = cli.encryption_key_file.as_ref() {
        if let Err(e) = opens(enc) {
            eprintln!("[ERROR] {}: {e}", enc.display());
            return 1;
        }
    }
    match keychain::store(account, &pass) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("[ERROR] {e}");
            1
        }
    }
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

/// Create (or, with `overwrite`, replace) a key file with mode 0600 from the
/// first byte. The old write-then-chmod sequence left a window in which the
/// file existed with the umask default (typically 0644) and its full
/// contents — ciphertext normally, the raw private key under
/// `--unsafe-plaintext-key` — readable by any local account. Setting the
/// mode at `open()` and using `create_new` when not overwriting closes both
/// that window and the silent-clobber path (audit 2026-09-04).
fn write_key_file_0600(path: &Path, payload: &[u8], overwrite: bool) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true);
    if overwrite {
        opts.create(true).truncate(true);
    } else {
        opts.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    file.write_all(payload)?;
    file.sync_all()
}

/// Persist a freshly-minted 32-byte key to disk, encrypted with
/// `passphrase` when present, or plaintext otherwise. Shared writer for
/// Ed25519 and X25519 key files — the encrypted format is identical.
/// Refuses to replace an existing file unless `overwrite` (`--force`).
fn save_key_bytes(path: &Path, key_bytes: &[u8; 32], passphrase: Option<&str>, overwrite: bool) {
    if !overwrite && path.exists() {
        eprintln!(
            "[ERROR] Key file already exists: {}. Refusing to overwrite — the DID is derived \
             from this key and regenerating would orphan every credential enrolled against it. \
             Pass --force to replace it deliberately.",
            path.display()
        );
        std::process::exit(1);
    }
    let payload: Vec<u8> = match passphrase {
        Some(pass) => encrypt_key(key_bytes, pass),
        None => {
            eprintln!(
                "[WARN] Saving key in PLAINTEXT (--unsafe-plaintext-key). Do NOT use in production."
            );
            key_bytes.to_vec()
        }
    };
    if let Err(e) = write_key_file_0600(path, &payload, overwrite) {
        eprintln!("[ERROR] Cannot write key file {}: {}", path.display(), e);
        std::process::exit(1);
    }
    // Belt and braces for the --force path, where an existing file keeps
    // whatever mode it had.
    chmod_key_file(path);
}

/// Read a 32-byte key from disk. Accepts either plaintext (32 raw
/// bytes) or the encrypted format and decrypts with `passphrase` when
/// provided.
/// Whether `passphrase` opens the encrypted key file at `path`.
fn load_key_bytes_checked(path: &Path, passphrase: &str) -> Result<(), String> {
    let data = std::fs::read(path).map_err(|e| format!("cannot read the key file: {e}"))?;
    decrypt_key(&data, passphrase).map(|_| ())
}

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
fn generate_and_save_key(path: &Path, passphrase: Option<&str>, overwrite: bool) -> SigningKey {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    save_key_bytes(path, &signing_key.to_bytes(), passphrase, overwrite);

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
fn generate_and_save_encryption_secret(
    path: &Path,
    passphrase: Option<&str>,
    overwrite: bool,
) -> StaticSecret {
    // Raw 32-byte seed ⇒ StaticSecret (clamping happens during DH).
    // Using `rand::random` keeps the RNG source identical to the
    // Ed25519 path above and avoids taking another crate.
    let raw: [u8; 32] = rand::random();
    let secret = StaticSecret::from(raw);
    let public = X25519PublicKey::from(&secret);
    save_key_bytes(path, &secret.to_bytes(), passphrase, overwrite);

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

/// Compact JWS proving the new signing key belongs to the enrolling daemon:
/// EdDSA over `{credential_id, iat}`, as the activate endpoint expects.
fn build_enrollment_proof(key: &SigningKey, credential_id: &str, iat: i64) -> String {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD
        .encode(serde_json::json!({ "credential_id": credential_id, "iat": iat }).to_string());
    let signing_input = format!("{header}.{payload}");
    let signature = key.sign(signing_input.as_bytes());
    format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}

/// `--enroll`: generate both keys, activate the credential, exit. Returns
/// the process exit code.
/// File names inside an `--enroll --dir` directory.
const DIR_SIGNING_KEY: &str = "signing.key.enc";
const DIR_ENCRYPTION_KEY: &str = "encryption.key.enc";
const DIR_AGENT_ENV: &str = "agent.env";

/// `agent.env` for `scripts/run_noninteractive_stack.sh start <dir>`: plain
/// KEY=VALUE lines the script reads without evaluating them.
fn agent_env_contents(
    api_url: &str,
    aid: &str,
    credential_id: &str,
    key_file: &Path,
    encryption_key_file: &Path,
) -> String {
    format!(
        "# Written by nexusinbox-signer --enroll or --connect. Read by scripts/run_noninteractive_stack.sh.\n\
         AGENT_INBOX_API_URL={api_url}\n\
         AGENT_INBOX_AID={aid}\n\
         AGENT_INBOX_CREDENTIAL_ID={credential_id}\n\
         AGENT_INBOX_KEY_FILE={}\n\
         AGENT_INBOX_ENCRYPTION_KEY_FILE={}\n\
         AGENT_INBOX_MODE_A_EXECUTOR=on\n",
        key_file.display(),
        encryption_key_file.display()
    )
}

/// Create the agent directory (mode 0700) if it does not exist yet.
fn ensure_agent_dir(dir: &Path) -> std::io::Result<()> {
    if dir.exists() {
        return Ok(());
    }
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

async fn run_enroll(cli: &Cli) -> i32 {
    let Some(credential_id) = cli.credential_id.as_deref() else {
        eprintln!("[ERROR] --enroll needs --credential-id (shown in the web UI)");
        return 2;
    };
    // It goes into the request path.
    if uuid::Uuid::parse_str(credential_id).is_err() {
        eprintln!("[ERROR] --credential-id must be a UUID");
        return 2;
    }
    // With --dir, the key files live there unless given explicitly.
    let agent_dir = match cli.dir.as_ref() {
        Some(dir) => {
            if let Err(e) = ensure_agent_dir(dir) {
                eprintln!("[ERROR] Cannot create {}: {e}", dir.display());
                return 2;
            }
            match std::fs::canonicalize(dir) {
                Ok(dir) => Some(dir),
                Err(e) => {
                    eprintln!("[ERROR] Cannot use {}: {e}", dir.display());
                    return 2;
                }
            }
        }
        None => None,
    };
    let key_file = match agent_dir.as_ref() {
        Some(dir) if cli.key_file == Path::new(DIR_SIGNING_KEY) => dir.join(DIR_SIGNING_KEY),
        _ => cli.key_file.clone(),
    };
    let Some(encryption_key_file) = cli
        .encryption_key_file
        .clone()
        .or_else(|| agent_dir.as_ref().map(|dir| dir.join(DIR_ENCRYPTION_KEY)))
    else {
        eprintln!(
            "[ERROR] --enroll needs --dir (or --encryption-key-file): the daemon holds the agent's receiving key"
        );
        return 2;
    };
    let encryption_key_file = &encryption_key_file;
    // Check both files before asking for anything, so a refusal never
    // leaves one new key written and the other missing.
    if !cli.force {
        for path in [&key_file, encryption_key_file] {
            if path.exists() {
                eprintln!(
                    "[ERROR] Key file already exists: {}. Pass --force to replace it.",
                    path.display()
                );
                return 2;
            }
        }
    }
    let enrollment_secret = match std::env::var("AGENT_INBOX_ENROLLMENT_SECRET") {
        Ok(value) if !value.trim().is_empty() => value.trim().to_string(),
        _ => read_passphrase("Enter the enrollment secret shown in the web UI: "),
    };
    if enrollment_secret.is_empty() {
        eprintln!("[ERROR] The enrollment secret is empty.");
        return 2;
    }

    let (aid, did) = match activate_with_new_keys(
        cli,
        credential_id,
        &enrollment_secret,
        &key_file,
        encryption_key_file,
        None,
    )
    .await
    {
        Ok(activated) => activated,
        Err(Refused::Unreachable(e)) => {
            eprintln!("[ERROR] activation request failed: {e}");
            eprintln!(
                "[ERROR] The keys were written. Rerun with --force once the API is reachable."
            );
            return 1;
        }
        Err(Refused::Rejected(status, message)) => {
            eprintln!("[ERROR] activation was refused ({status}): {message}");
            eprintln!(
                "[ERROR] The keys were written but are not enrolled. Fix the cause above and rerun with --force; if the credential has expired, create a new one in the web UI."
            );
            return 1;
        }
    };
    let (aid, did) = (aid.as_str(), did.as_str());
    eprintln!("[INFO] Enrolled.");
    eprintln!("[INFO]   AID:           {aid}");
    eprintln!("[INFO]   DID:           {did}");
    eprintln!("[INFO]   Credential ID: {credential_id}");
    let Some(dir) = agent_dir else {
        eprintln!("[INFO] Start the daemon with the same --key-file, --encryption-key-file and --api-url, plus:");
        eprintln!("[INFO]   --aid {aid} --credential-id {credential_id}");
        return 0;
    };
    let env_path = dir.join(DIR_AGENT_ENV);
    let contents = agent_env_contents(
        cli.api_url.trim_end_matches('/'),
        aid,
        credential_id,
        &key_file,
        encryption_key_file,
    );
    if let Err(e) = write_key_file_0600(&env_path, contents.as_bytes(), true) {
        eprintln!(
            "[ERROR] Enrolled, but could not write {}: {e}",
            env_path.display()
        );
        eprintln!("[INFO] Start the daemon with --aid {aid} --credential-id {credential_id}");
        return 1;
    }
    eprintln!("[INFO] Saved the settings to {}.", env_path.display());
    eprintln!("[INFO] Start the daemon and gateway from the repository root with:");
    eprintln!(
        "[INFO]   scripts/run_noninteractive_stack.sh start {}",
        dir.display()
    );
    0
}

/// Why an activation did not happen.
enum Refused {
    /// The API could not be reached.
    Unreachable(String),
    /// The API answered with an error: status and message.
    Rejected(reqwest::StatusCode, String),
}

/// Ask for a new passphrase, write both keys with it, and register their
/// public halves with the credential. Returns the agent's AID and the new
/// DID. The key files are written before the request, so on an error they
/// exist but are not enrolled.
async fn activate_with_new_keys(
    cli: &Cli,
    credential_id: &str,
    enrollment_secret: &str,
    key_file: &Path,
    encryption_key_file: &Path,
    device_label: Option<&str>,
) -> Result<(String, String), Refused> {
    let passphrase = prompt_new_passphrase(cli.unsafe_plaintext_key);
    let signing_key = generate_and_save_key(key_file, passphrase.as_deref(), cli.force);
    let encryption_secret =
        generate_and_save_encryption_secret(encryption_key_file, passphrase.as_deref(), cli.force);

    let mut body = serde_json::json!({
        "enrollment_secret": enrollment_secret,
        "signing_public_key": URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
        "encryption_public_key":
            URL_SAFE_NO_PAD.encode(X25519PublicKey::from(&encryption_secret).as_bytes()),
        "enrollment_proof": build_enrollment_proof(&signing_key, credential_id, Utc::now().timestamp()),
        "key_holder": "signer_daemon",
    });
    if let Some(label) = device_label {
        body["device_label"] = serde_json::json!(label);
    }
    let url = format!(
        "{}/agent-credentials/{}/activate",
        cli.api_url.trim_end_matches('/'),
        credential_id
    );
    let (status, text) = post_json(&url, &body).await.map_err(Refused::Unreachable)?;
    if !status.is_success() {
        return Err(Refused::Rejected(status, error_message(&text)));
    }
    let activated: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
    Ok((
        activated["aid"].as_str().unwrap_or("?").to_string(),
        activated["did"].as_str().unwrap_or("?").to_string(),
    ))
}

async fn post_json(
    url: &str,
    body: &serde_json::Value,
) -> Result<(reqwest::StatusCode, String), String> {
    let response = reqwest::Client::new()
        .post(url)
        .json(body)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = response.status();
    Ok((status, response.text().await.unwrap_or_default()))
}

/// The `message` of an API error body, or the start of the body.
fn error_message(text: &str) -> String {
    serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .and_then(|v| v.get("message").and_then(|m| m.as_str()).map(String::from))
        .unwrap_or_else(|| text.chars().take(200).collect())
}

/// Pairing codes as the API issues them: Crockford base32, 10 symbols,
/// shown as `XXXXX-XXXXX`. Accept them as typed — any case, with dashes or
/// spaces, O for 0 and I or L for 1 — the way the API does.
const PAIRING_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

fn normalize_pairing_code(raw: &str) -> Option<String> {
    let mut out = String::with_capacity(10);
    for c in raw.chars() {
        if c == '-' || c.is_whitespace() {
            continue;
        }
        if !c.is_ascii() {
            return None;
        }
        let c = match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            other => other,
        };
        if !PAIRING_ALPHABET.contains(&(c as u8)) {
            return None;
        }
        out.push(c);
    }
    (out.len() == 10).then_some(out)
}

/// The directory under ~/.nexusinbox for an agent, named after it the way
/// the web UI names it (apps/web/lib/agents/enroll-command.ts): lowercase
/// letters, digits and dashes, at most 32 characters, else `agent-` and
/// the end of the AID.
fn agent_dir_name(label: &str, aid: &str) -> String {
    let mut slug = String::new();
    for c in label.to_lowercase().chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            slug.push(c);
        } else if !slug.ends_with('-') {
            slug.push('-');
        }
    }
    let slug: String = slug.trim_matches('-').chars().take(32).collect();
    let slug = slug.trim_end_matches('-');
    if !slug.is_empty() {
        return slug.to_string();
    }
    let tail: Vec<char> = aid
        .trim_start_matches("aid:ai:")
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect();
    let tail: String = tail[tail.len().saturating_sub(8)..].iter().collect();
    format!("agent-{}", tail.to_lowercase())
}

/// The first of `<name>`, `<name>-2`, … under `base` that holds no agent
/// yet, so connecting never touches another agent's keys.
fn free_agent_dir(base: &Path, name: &str) -> Option<PathBuf> {
    (1..100)
        .map(|n| match n {
            1 => base.join(name),
            n => base.join(format!("{name}-{n}")),
        })
        .find(|dir| {
            [DIR_SIGNING_KEY, DIR_ENCRYPTION_KEY, DIR_AGENT_ENV]
                .iter()
                .all(|file| !dir.join(file).exists())
        })
}

/// What the credential is labelled with once this machine connects: the
/// kind of system only. The hostname is not sent; it often carries the
/// person's name, and the service keeps as little as it can.
fn device_label() -> &'static str {
    match std::env::consts::OS {
        "macos" => "macOS",
        "linux" => "Linux",
        "windows" => "Windows",
        other => other,
    }
}

/// `--connect <code>`: see the flag. Returns the process exit code.
async fn run_connect(cli: &Cli, raw_code: &str) -> i32 {
    let Some(code) = normalize_pairing_code(raw_code) else {
        eprintln!("[ERROR] A pairing code is 10 letters and digits, like 7KQ4P-ZX9M2.");
        return 2;
    };
    let api_url = cli.api_url.trim_end_matches('/');
    let (status, text) = match post_json(
        &format!("{api_url}/agent-pairing/resolve"),
        &serde_json::json!({ "pairing_code": code }),
    )
    .await
    {
        Ok(answer) => answer,
        Err(e) => {
            eprintln!("[ERROR] Could not reach {api_url}: {e}");
            return 1;
        }
    };
    match status {
        s if s.is_success() => {}
        reqwest::StatusCode::NOT_FOUND => {
            eprintln!("[ERROR] This pairing code is not valid any more: codes work once, for 10 minutes. Show a new one in the web UI and run the command again.");
            return 1;
        }
        reqwest::StatusCode::TOO_MANY_REQUESTS => {
            eprintln!(
                "[ERROR] Too many attempts from this network. Wait 10 minutes and try again."
            );
            return 1;
        }
        s => {
            eprintln!(
                "[ERROR] The pairing code was refused ({s}): {}",
                error_message(&text)
            );
            return 1;
        }
    }
    let found: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
    let (Some(credential_id), Some(aid), Some(agent_label)) = (
        found["credential_id"]
            .as_str()
            .filter(|id| uuid::Uuid::parse_str(id).is_ok()),
        found["aid"].as_str(),
        found["agent_label"].as_str(),
    ) else {
        eprintln!("[ERROR] Unexpected answer from {api_url}");
        return 1;
    };

    let dir = match cli.dir.clone() {
        Some(dir) => dir,
        None => {
            let Some(home) = std::env::var_os("HOME") else {
                eprintln!("[ERROR] HOME is not set; pass --dir.");
                return 2;
            };
            let base = PathBuf::from(home).join(".nexusinbox");
            if let Err(e) = ensure_agent_dir(&base) {
                eprintln!("[ERROR] Cannot create {}: {e}", base.display());
                return 2;
            }
            match free_agent_dir(&base, &agent_dir_name(agent_label, aid)) {
                Some(dir) => dir,
                None => {
                    eprintln!(
                        "[ERROR] No free directory for this agent under {}; pass --dir.",
                        base.display()
                    );
                    return 2;
                }
            }
        }
    };
    let created_dir = !dir.exists();
    if let Err(e) = ensure_agent_dir(&dir) {
        eprintln!("[ERROR] Cannot create {}: {e}", dir.display());
        return 2;
    }
    let dir = match std::fs::canonicalize(&dir) {
        Ok(dir) => dir,
        Err(e) => {
            eprintln!("[ERROR] Cannot use {}: {e}", dir.display());
            return 2;
        }
    };
    let key_file = dir.join(DIR_SIGNING_KEY);
    let encryption_key_file = dir.join(DIR_ENCRYPTION_KEY);
    if !cli.force {
        for path in [&key_file, &encryption_key_file] {
            if path.exists() {
                eprintln!(
                    "[ERROR] {} already holds an agent's keys. Choose another --dir.",
                    dir.display()
                );
                return 2;
            }
        }
    }

    eprintln!("[INFO] Connecting this machine to \"{agent_label}\".");
    let refused = match activate_with_new_keys(
        cli,
        credential_id,
        &code,
        &key_file,
        &encryption_key_file,
        Some(device_label()),
    )
    .await
    {
        Ok((activated_aid, _)) => {
            let contents = agent_env_contents(
                api_url,
                &activated_aid,
                credential_id,
                &key_file,
                &encryption_key_file,
            );
            let env_path = dir.join(DIR_AGENT_ENV);
            if let Err(e) = write_key_file_0600(&env_path, contents.as_bytes(), true) {
                eprintln!(
                    "[ERROR] Connected, but could not write {}: {e}",
                    env_path.display()
                );
                return 1;
            }
            eprintln!(
                "[INFO] Connected. The keys and settings are in {}.",
                dir.display()
            );
            println!("{}", dir.display());
            return 0;
        }
        Err(Refused::Unreachable(e)) => format!("could not reach {api_url}: {e}"),
        Err(Refused::Rejected(status, message)) => format!("refused ({status}): {message}"),
    };
    // Keys that were never enrolled are no use to anyone: remove them, so
    // the next attempt starts from the same, empty directory.
    let _ = std::fs::remove_file(&key_file);
    let _ = std::fs::remove_file(&encryption_key_file);
    if created_dir {
        let _ = std::fs::remove_dir(&dir);
    }
    eprintln!("[ERROR] Connecting failed: {refused}");
    eprintln!("[ERROR] Nothing was kept. Show a new code in the web UI and run the command again.");
    1
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if let Some(code) = cli.connect.as_deref() {
        std::process::exit(run_connect(&cli, code).await);
    }
    if cli.enroll {
        std::process::exit(run_enroll(&cli).await);
    }
    if cli.dir.is_some() {
        eprintln!("[ERROR] --dir is for --enroll and --connect; to run, use scripts/run_noninteractive_stack.sh start <dir>");
        std::process::exit(2);
    }

    if let Some(account) = cli.keychain_delete.as_deref() {
        match keychain::delete(account) {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                eprintln!("[ERROR] {e}");
                std::process::exit(1);
            }
        }
    }
    if let Some(account) = cli.keychain_store.as_deref() {
        std::process::exit(run_keychain_store(&cli, account));
    }

    // Key management — single passphrase prompt for both Ed25519 and
    // optional X25519 key files, so the operator doesn't have to type
    // it twice per boot. Started at login, it comes from the keychain.
    let passphrase: Option<String> = if cli.generate {
        prompt_new_passphrase(cli.unsafe_plaintext_key)
    } else if let Some(account) = cli.passphrase_from_keychain.as_deref() {
        match keychain::load(account) {
            Ok(pass) => Some(pass),
            Err(e) => {
                eprintln!("[ERROR] {e}");
                std::process::exit(1);
            }
        }
    } else if !cli.unsafe_plaintext_key {
        prompt_unlock_passphrase(false)
    } else {
        None
    };

    let signing_key = if cli.generate {
        generate_and_save_key(&cli.key_file, passphrase.as_deref(), cli.force)
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
                generate_and_save_encryption_secret(enc_path, passphrase.as_deref(), cli.force)
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

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                // SO_PEERCRED check (§4.3 IPC security). When --allowed-uid is
                // unset we default to the daemon's own uid, so an unconfigured
                // deployment still rejects other users on the host instead of
                // accepting everyone. We deliberately do NOT special-case
                // uid 0: a local root process bypassing the gateway to call
                // sign_assertion / unwrap_content_key directly is exactly the
                // path this check exists to close.
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

/// Upper bound for one JSON-RPC line on the UDS. A plain `read_line` buffers
/// until it sees `\n`, so a single peer could grow one line until the
/// process OOMs (audit 2026-09-04). 64 KiB is ~100x the largest legitimate
/// request (a wrap/unwrap carrying a base64 envelope).
const MAX_RPC_LINE_BYTES: usize = 64 * 1024;

/// `read_line` with a byte cap. Returns `Ok(0)` at EOF, `Ok(n)` after
/// appending a full line (newline included) to `line`, or an `InvalidData`
/// error as soon as `max` bytes accumulate without a newline — the caller
/// drops the connection.
async fn read_line_bounded<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
    line: &mut String,
    max: usize,
) -> std::io::Result<usize> {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let (done, consumed) = {
            let available = reader.fill_buf().await?;
            if available.is_empty() {
                (true, 0)
            } else if let Some(i) = available.iter().position(|&b| b == b'\n') {
                buf.extend_from_slice(&available[..=i]);
                (true, i + 1)
            } else {
                buf.extend_from_slice(available);
                (false, available.len())
            }
        };
        reader.consume(consumed);
        if buf.len() > max {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("rpc line exceeds {max} bytes"),
            ));
        }
        if done {
            break;
        }
    }
    let n = buf.len();
    let text = String::from_utf8(buf).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "rpc line is not valid UTF-8",
        )
    })?;
    line.push_str(&text);
    Ok(n)
}

async fn handle_connection(state: Arc<DaemonState>, stream: tokio::net::UnixStream) {
    let (reader, mut writer) = stream.into_split();
    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();

    loop {
        line.clear();
        match read_line_bounded(&mut buf_reader, &mut line, MAX_RPC_LINE_BYTES).await {
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
    fn test_write_key_file_0600_refuses_overwrite_and_sets_mode() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "nexusinbox-signer-keytest-{}.key",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);

        // First write creates the file with 0600 from the start.
        write_key_file_0600(&path, b"first", false).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "key file must be created 0600, got {mode:o}");
        }
        assert_eq!(std::fs::read(&path).unwrap(), b"first");

        // Without overwrite, an existing file is refused (create_new) and
        // its contents are untouched — this is what protects a live key
        // from a stray `--generate`.
        let err = write_key_file_0600(&path, b"second", false).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path).unwrap(), b"first");

        // With overwrite (--force) the file is replaced.
        write_key_file_0600(&path, b"third", true).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"third");

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn test_read_line_bounded_caps_oversized_lines() {
        let mut r = BufReader::new(&b"{\"id\":1}\nrest"[..]);
        let mut line = String::new();
        let n = read_line_bounded(&mut r, &mut line, 64).await.unwrap();
        assert_eq!(n, 9);
        assert_eq!(line, "{\"id\":1}\n");

        // Oversized line with no newline → InvalidData; the daemon drops
        // the connection instead of buffering until OOM.
        let big = vec![b'x'; 200];
        let mut r = BufReader::new(&big[..]);
        let mut line = String::new();
        let err = read_line_bounded(&mut r, &mut line, 64).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

        let mut big_nl = vec![b'y'; 100];
        big_nl.push(b'\n');
        let mut r = BufReader::new(&big_nl[..]);
        let mut line = String::new();
        assert!(read_line_bounded(&mut r, &mut line, 64).await.is_err());

        let mut r = BufReader::new(&b""[..]);
        let mut line = String::new();
        assert_eq!(read_line_bounded(&mut r, &mut line, 64).await.unwrap(), 0);
        assert!(line.is_empty());
    }

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
    fn agent_env_lists_what_the_start_script_needs() {
        let env = agent_env_contents(
            "https://api.example",
            "aid:ai:01TEST",
            "00000000-0000-4000-8000-000000000000",
            Path::new("/home/a/.nexusinbox/x/signing.key.enc"),
            Path::new("/home/a/.nexusinbox/x/encryption.key.enc"),
        );
        let lines: Vec<&str> = env.lines().filter(|l| !l.starts_with('#')).collect();
        assert_eq!(
            lines,
            [
                "AGENT_INBOX_API_URL=https://api.example",
                "AGENT_INBOX_AID=aid:ai:01TEST",
                "AGENT_INBOX_CREDENTIAL_ID=00000000-0000-4000-8000-000000000000",
                "AGENT_INBOX_KEY_FILE=/home/a/.nexusinbox/x/signing.key.enc",
                "AGENT_INBOX_ENCRYPTION_KEY_FILE=/home/a/.nexusinbox/x/encryption.key.enc",
                "AGENT_INBOX_MODE_A_EXECUTOR=on",
            ]
        );
    }

    #[test]
    fn pairing_codes_are_read_as_typed() {
        assert_eq!(
            normalize_pairing_code("7kq4p-zx9m2").as_deref(),
            Some("7KQ4PZX9M2")
        );
        assert_eq!(
            normalize_pairing_code(" 7KQ4P ZX9M2 ").as_deref(),
            Some("7KQ4PZX9M2")
        );
        assert_eq!(
            normalize_pairing_code("OIL00-11111").as_deref(),
            Some("0110011111")
        );
        for bad in [
            "",
            "7KQ4P-ZX9M",
            "7KQ4P-ZX9M22",
            "7KQ4P-ZX9MU",
            "ens_abcdefghij",
        ] {
            assert_eq!(normalize_pairing_code(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn agent_directories_are_named_like_the_web_names_them() {
        // The same cases as apps/web/lib/agents/enroll-command.test.ts.
        assert_eq!(
            agent_dir_name("enroll-test", "aid:ai:01M6W9J3TAQPHX7R3W591MMFYF"),
            "enroll-test"
        );
        assert_eq!(
            agent_dir_name("  First Secretary!  ", "aid:ai:X"),
            "first-secretary"
        );
        assert_eq!(
            agent_dir_name(&format!("{}-b", "a".repeat(40)), "aid:ai:X"),
            "a".repeat(32)
        );
        assert_eq!(
            agent_dir_name("秘書", "aid:ai:01M6W9J3TAQPHX7R3W591MMFYF"),
            "agent-591mmfyf"
        );
        // Whatever the server sends, the name stays inside the base.
        assert_eq!(agent_dir_name("../..", "aid:ai:../../x"), "agent-x");
    }

    #[test]
    fn connecting_never_reuses_a_directory_that_holds_an_agent() {
        let base =
            std::env::temp_dir().join(format!("nexusinbox-signer-dirtest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        assert_eq!(
            free_agent_dir(base.as_path(), "secretary").unwrap(),
            base.as_path().join("secretary")
        );
        // An empty directory, or one with only run/, is free.
        std::fs::create_dir_all(base.as_path().join("secretary/run")).unwrap();
        assert_eq!(
            free_agent_dir(base.as_path(), "secretary").unwrap(),
            base.as_path().join("secretary")
        );
        std::fs::write(base.as_path().join("secretary").join(DIR_AGENT_ENV), "").unwrap();
        assert_eq!(
            free_agent_dir(base.as_path(), "secretary").unwrap(),
            base.as_path().join("secretary-2")
        );
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn enrollment_proof_is_a_jws_over_the_credential_id() {
        use ed25519_dalek::Signature;
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let proof = build_enrollment_proof(&key, "cred-123", 1_700_000_000);
        let parts: Vec<&str> = proof.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["alg"], "EdDSA");
        let payload: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(payload["credential_id"], "cred-123");
        assert_eq!(payload["iat"], 1_700_000_000);
        let signature_bytes: [u8; 64] = URL_SAFE_NO_PAD
            .decode(parts[2])
            .unwrap()
            .try_into()
            .unwrap();
        key.verifying_key()
            .verify(
                format!("{}.{}", parts[0], parts[1]).as_bytes(),
                &Signature::from_bytes(&signature_bytes),
            )
            .expect("the proof verifies with the new key");
    }

    /// Shared vector (tests/vectors/envelope_signing.json): the daemon signs
    /// exactly the bytes the API verifies and the web signs (docs/29 §2.4).
    #[test]
    fn envelope_signing_matches_shared_vector() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/vectors/envelope_signing.json"
        )))
        .unwrap();
        let field = |name: &str| vector["fields"][name].as_str().unwrap().to_string();
        let params = SignEnvelopeParams {
            sender_did: field("sender_did"),
            recipient_did: field("recipient_did"),
            subject_encrypted: field("subject_encrypted"),
            encrypted_content: field("encrypted_content"),
            encrypted_key: field("encrypted_key"),
            nonce: field("nonce"),
        };
        let payload = build_envelope_signing_payload(&params);
        assert_eq!(payload, vector["payload"].as_str().unwrap());

        let seed_hex = vector["signing_seed_hex"].as_str().unwrap();
        let mut seed = [0u8; 32];
        for (i, byte) in seed.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&seed_hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        let key = SigningKey::from_bytes(&seed);
        assert_eq!(
            URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()),
            vector["public_key_b64url"].as_str().unwrap()
        );
        let signature = URL_SAFE_NO_PAD.encode(key.sign(payload.as_bytes()).to_bytes());
        assert_eq!(signature, vector["signature_b64url"].as_str().unwrap());
    }

    /// Shared vector (tests/vectors/x25519_wrap.json): keys wrapped by the
    /// web and by this daemon both unwrap here (docs/29 §4).
    #[test]
    fn x25519_wrap_matches_shared_vector() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/vectors/x25519_wrap.json"
        )))
        .unwrap();
        let private: [u8; 32] = URL_SAFE_NO_PAD
            .decode(vector["recipient_private_key_b64url"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let secret = StaticSecret::from(private);
        assert_eq!(
            URL_SAFE_NO_PAD.encode(X25519PublicKey::from(&secret).as_bytes()),
            vector["recipient_public_key_b64url"].as_str().unwrap()
        );
        let content_key = vector["content_key"].as_str().unwrap();
        for (origin, wrapped) in vector["wrapped_keys"].as_object().unwrap() {
            assert_eq!(
                unwrap_content_key(&secret, wrapped.as_str().unwrap()).unwrap(),
                content_key,
                "wrapped by {origin}"
            );
        }
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
