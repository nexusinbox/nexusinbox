// Phase 4.4c+ (docs/25c-a §2.2) — Rust-side envelope AES-GCM that is
// bit-compatible with the TypeScript `encryptText` contract
// (packages/crypto). Gateway uses it to seal outgoing auto-reply
// subjects / bodies with a freshly generated content key before the
// daemon wraps that content key for the recipient.
//
// Serialised format:
//   enc:v1:PBKDF2-SHA256:AES-GCM-256:<iter>:<salt_b64url>:<iv_b64url>:<ct_b64url>
//
// Matches packages/crypto/src/index.ts `serializeEncryptedPayload`.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce as AesNonce};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::RngCore;
use sha2::Sha256;

const ENVELOPE_VERSION: u32 = 1;
const PBKDF2_ITERATIONS: u32 = 120_000;
const SALT_BYTES: usize = 16;
const IV_BYTES: usize = 12;
const AES_KEY_BYTES: usize = 32;

pub struct EncryptedEnvelope {
    /// `enc:v1:...` formatted string the API accepts verbatim.
    pub serialized: String,
    /// Base64url-encoded 12-byte AES-GCM nonce. The server stores this
    /// alongside the envelope so signature verification can replay
    /// the exact bytes; the API wire format exposes it as its own
    /// field even though it is already part of `serialized`.
    pub nonce_b64url: String,
}

fn to_b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn derive_key(
    passphrase: &str,
    salt: &[u8],
    iterations: u32,
) -> Result<[u8; AES_KEY_BYTES], String> {
    let mut out = [0u8; AES_KEY_BYTES];
    pbkdf2::<Hmac<Sha256>>(passphrase.as_bytes(), salt, iterations, &mut out)
        .map_err(|e| format!("pbkdf2 failed: {e}"))?;
    Ok(out)
}

/// Produce a random 32-byte AES-256 content key, serialised as
/// base64url — matches `generateContentKey()` on the TS side so the
/// daemon's wrap_content_key receives the exact shape browsers do.
pub fn generate_content_key() -> String {
    let mut bytes = [0u8; AES_KEY_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    to_b64url(&bytes)
}

/// Encrypt `plaintext` with AES-256-GCM using the content key as the
/// PBKDF2 passphrase. The resulting `serialized` string is what
/// clients eventually decrypt via `decryptText` in packages/crypto.
pub fn encrypt_envelope_text(
    plaintext: &str,
    content_key: &str,
) -> Result<EncryptedEnvelope, String> {
    let mut salt = [0u8; SALT_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let mut iv = [0u8; IV_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut iv);

    let key = derive_key(content_key, &salt, PBKDF2_ITERATIONS)?;
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| format!("AES-GCM init failed: {e}"))?;
    let nonce = AesNonce::from_slice(&iv);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| format!("AES-GCM encrypt failed: {e}"))?;

    let serialized = format!(
        "enc:v{v}:PBKDF2-SHA256:AES-GCM-256:{iter}:{salt}:{iv}:{ct}",
        v = ENVELOPE_VERSION,
        iter = PBKDF2_ITERATIONS,
        salt = to_b64url(&salt),
        iv = to_b64url(&iv),
        ct = to_b64url(&ciphertext),
    );

    Ok(EncryptedEnvelope {
        serialized,
        nonce_b64url: to_b64url(&iv),
    })
}

/// Decrypt a TS-produced `enc:v1:...` string. The executor uses
/// this to read incoming A2A bodies after the daemon has unwrapped
/// the content key via `unwrap_content_key`. Clients produced the
/// ciphertext with packages/crypto's `encryptText`, so the two sides
/// must stay in lockstep on salt / iteration / KDF.
pub fn decrypt_envelope_text(serialized: &str, content_key: &str) -> Result<String, String> {
    let parts: Vec<&str> = serialized.split(':').collect();
    if parts.len() != 8 || parts[0] != "enc" {
        return Err(format!("invalid envelope format: {} parts", parts.len()));
    }
    if parts[1] != "v1" || parts[2] != "PBKDF2-SHA256" || parts[3] != "AES-GCM-256" {
        return Err("unsupported envelope header".into());
    }
    let iterations: u32 = parts[4].parse().map_err(|_| "bad iter".to_string())?;
    let salt = URL_SAFE_NO_PAD
        .decode(parts[5])
        .map_err(|e| format!("salt: {e}"))?;
    let iv = URL_SAFE_NO_PAD
        .decode(parts[6])
        .map_err(|e| format!("iv: {e}"))?;
    let ct = URL_SAFE_NO_PAD
        .decode(parts[7])
        .map_err(|e| format!("ct: {e}"))?;
    let key = derive_key(content_key, &salt, iterations)?;
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| format!("AES-GCM init failed: {e}"))?;
    let nonce = AesNonce::from_slice(&iv);
    let plaintext = cipher
        .decrypt(nonce, ct.as_ref())
        .map_err(|e| format!("AES-GCM decrypt failed: {e}"))?;
    String::from_utf8(plaintext).map_err(|e| format!("utf8: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_content_key_yields_32_bytes_b64url() {
        let k = generate_content_key();
        // base64url without padding of 32 bytes → 43 characters.
        assert_eq!(k.len(), 43);
        let bytes = URL_SAFE_NO_PAD.decode(&k).expect("b64url decode");
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn encrypt_then_decrypt_roundtrip() {
        let key = generate_content_key();
        let env = encrypt_envelope_text("hello world", &key).expect("encrypt");
        assert!(env
            .serialized
            .starts_with("enc:v1:PBKDF2-SHA256:AES-GCM-256:120000:"));
        let recovered = decrypt_envelope_text(&env.serialized, &key).expect("decrypt");
        assert_eq!(recovered, "hello world");
    }

    #[test]
    fn nonce_field_matches_serialized_iv() {
        let key = generate_content_key();
        let env = encrypt_envelope_text("x", &key).expect("encrypt");
        let parts: Vec<&str> = env.serialized.split(':').collect();
        assert_eq!(parts[6], env.nonce_b64url);
    }

    #[test]
    fn decrypt_fails_on_wrong_key() {
        let env = encrypt_envelope_text("secret", &generate_content_key()).expect("encrypt");
        let other = generate_content_key();
        assert!(decrypt_envelope_text(&env.serialized, &other).is_err());
    }

    #[test]
    fn decrypt_rejects_tampered_ciphertext() {
        let key = generate_content_key();
        let env = encrypt_envelope_text("immutable", &key).expect("encrypt");
        // Flip the last base64url char to corrupt the ciphertext; AES-GCM
        // auth tag fails closed, producing an Err.
        let mut mangled = env.serialized.clone();
        let last = mangled.pop().unwrap();
        mangled.push(if last == 'A' { 'B' } else { 'A' });
        assert!(decrypt_envelope_text(&mangled, &key).is_err());
    }
}
