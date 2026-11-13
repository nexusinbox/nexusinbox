//! Envelope signature v2 (docs/40 §14.2, §14.3). The gateway sends the
//! envelope with the body and each attachment's metadata already hashed;
//! the daemon writes the canonical JSON itself (keys sorted, no
//! whitespace, lists sorted), prefixes it and signs. The same bytes as
//! packages/core and services/api (tests/vectors/envelope_v2.json).

use serde::Deserialize;

pub const PREFIX: &str = "nexusinbox-envelope-v2\n";

/// How far `sent_at` may be from the daemon's clock (docs/40 §14.3).
pub const MAX_SKEW_SECS: i64 = 5 * 60;

#[derive(Clone, Deserialize)]
pub struct Wrap {
    pub did: String,
    pub key: String,
}

#[derive(Clone, Deserialize)]
pub struct AttachmentDigest {
    pub id: String,
    pub metadata_nonce: String,
    pub metadata_sha256: String,
}

/// The signed object without `v`, as the gateway sends it.
#[derive(Clone, Deserialize)]
pub struct SignEnvelopeV2Params {
    pub sender_aid: String,
    pub sender_did: String,
    pub recipient_aid: String,
    pub recipient_did: String,
    pub sent_at: String,
    pub content_type: String,
    pub thread_id: Option<String>,
    pub subject_encrypted: String,
    pub content_sha256: String,
    pub encrypted_key: String,
    pub nonce: String,
    pub sender_encrypted_key: Option<String>,
    #[serde(default)]
    pub encrypted_keys: Vec<Wrap>,
    #[serde(default)]
    pub sender_encrypted_keys: Vec<Wrap>,
    #[serde(default)]
    pub attachments: Vec<AttachmentDigest>,
}

fn s(value: &str) -> String {
    serde_json::to_string(value).expect("a string serializes")
}

fn opt(value: Option<&str>) -> String {
    value.map(s).unwrap_or_else(|| "null".to_string())
}

fn wraps(list: &[Wrap]) -> String {
    let mut sorted: Vec<&Wrap> = list.iter().collect();
    sorted.sort_by(|a, b| a.did.cmp(&b.did));
    let items: Vec<String> = sorted
        .iter()
        .map(|w| format!("{{\"did\":{},\"key\":{}}}", s(&w.did), s(&w.key)))
        .collect();
    format!("[{}]", items.join(","))
}

/// The bytes a v2 signature covers, as text.
pub fn signing_input(p: &SignEnvelopeV2Params) -> String {
    let mut attachments: Vec<&AttachmentDigest> = p.attachments.iter().collect();
    attachments.sort_by(|a, b| a.id.cmp(&b.id));
    let attachments: Vec<String> = attachments
        .iter()
        .map(|a| {
            format!(
                "{{\"id\":{},\"metadata_nonce\":{},\"metadata_sha256\":{}}}",
                s(&a.id),
                s(&a.metadata_nonce),
                s(&a.metadata_sha256)
            )
        })
        .collect();
    format!(
        "{PREFIX}{{\"attachments\":[{}],\"content_sha256\":{},\"content_type\":{},\"encrypted_key\":{},\"encrypted_keys\":{},\"nonce\":{},\"recipient_aid\":{},\"recipient_did\":{},\"sender_aid\":{},\"sender_did\":{},\"sender_encrypted_key\":{},\"sender_encrypted_keys\":{},\"sent_at\":{},\"subject_encrypted\":{},\"thread_id\":{},\"v\":2}}",
        attachments.join(","),
        s(&p.content_sha256),
        s(&p.content_type),
        s(&p.encrypted_key),
        wraps(&p.encrypted_keys),
        s(&p.nonce),
        s(&p.recipient_aid),
        s(&p.recipient_did),
        s(&p.sender_aid),
        s(&p.sender_did),
        opt(p.sender_encrypted_key.as_deref()),
        wraps(&p.sender_encrypted_keys),
        s(&p.sent_at),
        s(&p.subject_encrypted),
        opt(p.thread_id.as_deref()),
    )
}

/// Whether `sent_at` is RFC 3339 UTC with milliseconds and within
/// MAX_SKEW_SECS of `now`, so no one can have the daemon sign a message
/// dated to be replayed later.
pub fn sent_at_is_now(sent_at: &str, now: chrono::DateTime<chrono::Utc>) -> bool {
    if sent_at.len() != 24 || !sent_at.ends_with('Z') {
        return false;
    }
    match chrono::DateTime::parse_from_rfc3339(sent_at) {
        Ok(at) => (now.timestamp() - at.timestamp()).abs() <= MAX_SKEW_SECS,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};

    fn sha(text: &str) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(text.as_bytes()))
    }

    #[test]
    fn signs_the_shared_vectors() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/vectors/envelope_v2.json"
        );
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let seed_hex = v["signing_seed_hex"].as_str().unwrap();
        let seed: Vec<u8> = (0..32)
            .map(|i| u8::from_str_radix(&seed_hex[i * 2..i * 2 + 2], 16).unwrap())
            .collect();
        let key = SigningKey::from_bytes(&seed.try_into().unwrap());
        for c in v["cases"].as_array().unwrap() {
            let mut f = c["fields"].clone();
            f["content_sha256"] = sha(f["encrypted_content"].as_str().unwrap()).into();
            let attachments: Vec<serde_json::Value> = f["attachments"]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| {
                    serde_json::json!({
                        "id": a["id"],
                        "metadata_nonce": a["metadata_nonce"],
                        "metadata_sha256": sha(a["metadata_encrypted"].as_str().unwrap()),
                    })
                })
                .collect();
            f["attachments"] = attachments.into();
            let params: SignEnvelopeV2Params = serde_json::from_value(f).unwrap();
            let input = signing_input(&params);
            assert_eq!(input, c["signing_input"].as_str().unwrap());
            let signature = URL_SAFE_NO_PAD.encode(key.sign(input.as_bytes()).to_bytes());
            assert_eq!(signature, c["signature"].as_str().unwrap());
        }
    }

    #[test]
    fn sent_at_must_be_now() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-11-20T10:41:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        assert!(sent_at_is_now("2026-11-20T10:41:00.000Z", now));
        assert!(sent_at_is_now("2026-11-20T10:45:59.000Z", now));
        assert!(!sent_at_is_now("2026-11-20T10:46:01.000Z", now));
        assert!(!sent_at_is_now("2026-11-20T10:35:00.000Z", now));
        assert!(!sent_at_is_now("2026-11-20T10:41:00Z", now));
        assert!(!sent_at_is_now("2026-11-20T19:41:00.000+09:00", now));
    }
}
