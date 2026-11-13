//! Envelope signature v2 (docs/40 §14.2). The sending device signs
//! `nexusinbox-envelope-v2\n` followed by the envelope as canonical JSON
//! (keys sorted, no whitespace, RFC 8785). The body and each attachment's
//! encrypted metadata go in as SHA-256 hashes. packages/core,
//! services/agent-gateway and services/signer-daemon build the same bytes
//! (tests/vectors/envelope_v2.json).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use sha2::{Digest, Sha256};

pub const PREFIX: &str = "nexusinbox-envelope-v2\n";

pub struct Wrap<'a> {
    pub did: &'a str,
    pub key: &'a str,
}

pub struct Attachment<'a> {
    pub id: &'a str,
    pub metadata_encrypted: &'a str,
    pub metadata_nonce: &'a str,
}

pub struct Fields<'a> {
    pub sender_aid: &'a str,
    pub sender_did: &'a str,
    pub recipient_aid: &'a str,
    pub recipient_did: &'a str,
    pub sent_at: &'a str,
    pub content_type: &'a str,
    pub thread_id: Option<&'a str>,
    pub subject_encrypted: &'a str,
    pub encrypted_content: &'a str,
    pub encrypted_key: &'a str,
    pub nonce: &'a str,
    pub sender_encrypted_key: Option<&'a str>,
    pub encrypted_keys: Vec<Wrap<'a>>,
    pub sender_encrypted_keys: Vec<Wrap<'a>>,
    pub attachments: Vec<Attachment<'a>>,
}

pub fn sha256_b64(text: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(text.as_bytes()))
}

fn s(value: &str) -> String {
    serde_json::to_string(value).expect("a string serializes")
}

fn opt(value: Option<&str>) -> String {
    value.map(s).unwrap_or_else(|| "null".to_string())
}

fn wraps(list: &[Wrap<'_>]) -> String {
    let mut sorted: Vec<&Wrap<'_>> = list.iter().collect();
    sorted.sort_by(|a, b| a.did.cmp(b.did));
    let items: Vec<String> = sorted
        .iter()
        .map(|w| format!("{{\"did\":{},\"key\":{}}}", s(w.did), s(w.key)))
        .collect();
    format!("[{}]", items.join(","))
}

/// The bytes a v2 signature covers, as text.
pub fn signing_input(f: &Fields<'_>) -> String {
    let mut attachments: Vec<&Attachment<'_>> = f.attachments.iter().collect();
    attachments.sort_by(|a, b| a.id.cmp(b.id));
    let attachments: Vec<String> = attachments
        .iter()
        .map(|a| {
            format!(
                "{{\"id\":{},\"metadata_nonce\":{},\"metadata_sha256\":{}}}",
                s(a.id),
                s(a.metadata_nonce),
                s(&sha256_b64(a.metadata_encrypted))
            )
        })
        .collect();
    format!(
        "{PREFIX}{{\"attachments\":[{}],\"content_sha256\":{},\"content_type\":{},\"encrypted_key\":{},\"encrypted_keys\":{},\"nonce\":{},\"recipient_aid\":{},\"recipient_did\":{},\"sender_aid\":{},\"sender_did\":{},\"sender_encrypted_key\":{},\"sender_encrypted_keys\":{},\"sent_at\":{},\"subject_encrypted\":{},\"thread_id\":{},\"v\":2}}",
        attachments.join(","),
        s(&sha256_b64(f.encrypted_content)),
        s(f.content_type),
        s(f.encrypted_key),
        wraps(&f.encrypted_keys),
        s(f.nonce),
        s(f.recipient_aid),
        s(f.recipient_did),
        s(f.sender_aid),
        s(f.sender_did),
        opt(f.sender_encrypted_key),
        wraps(&f.sender_encrypted_keys),
        s(f.sent_at),
        s(f.subject_encrypted),
        opt(f.thread_id),
    )
}

/// A `sent_at` as senders write it: RFC 3339, UTC, milliseconds.
pub fn is_sent_at(value: &str) -> bool {
    value.len() == 24 && value.ends_with('Z') && chrono::DateTime::parse_from_rfc3339(value).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_input_matches_the_shared_vectors() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/vectors/envelope_v2.json"
        );
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        for c in v["cases"].as_array().unwrap() {
            let f = &c["fields"];
            let st = |k: &str| f[k].as_str().unwrap();
            let wraps = |k: &str| -> Vec<Wrap<'_>> {
                f[k].as_array()
                    .unwrap()
                    .iter()
                    .map(|w| Wrap {
                        did: w["did"].as_str().unwrap(),
                        key: w["key"].as_str().unwrap(),
                    })
                    .collect()
            };
            let fields = Fields {
                sender_aid: st("sender_aid"),
                sender_did: st("sender_did"),
                recipient_aid: st("recipient_aid"),
                recipient_did: st("recipient_did"),
                sent_at: st("sent_at"),
                content_type: st("content_type"),
                thread_id: f["thread_id"].as_str(),
                subject_encrypted: st("subject_encrypted"),
                encrypted_content: st("encrypted_content"),
                encrypted_key: st("encrypted_key"),
                nonce: st("nonce"),
                sender_encrypted_key: f["sender_encrypted_key"].as_str(),
                encrypted_keys: wraps("encrypted_keys"),
                sender_encrypted_keys: wraps("sender_encrypted_keys"),
                attachments: f["attachments"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|a| Attachment {
                        id: a["id"].as_str().unwrap(),
                        metadata_encrypted: a["metadata_encrypted"].as_str().unwrap(),
                        metadata_nonce: a["metadata_nonce"].as_str().unwrap(),
                    })
                    .collect(),
            };
            assert_eq!(signing_input(&fields), c["signing_input"].as_str().unwrap());
            let seed: [u8; 32] = (0..32)
                .map(|i| {
                    u8::from_str_radix(
                        &v["signing_seed_hex"].as_str().unwrap()[i * 2..i * 2 + 2],
                        16,
                    )
                    .unwrap()
                })
                .collect::<Vec<u8>>()
                .try_into()
                .unwrap();
            let key = ed25519_dalek::SigningKey::from_bytes(&seed);
            use ed25519_dalek::Signer as _;
            let signature =
                URL_SAFE_NO_PAD.encode(key.sign(signing_input(&fields).as_bytes()).to_bytes());
            assert_eq!(signature, c["signature"].as_str().unwrap());
            assert!(is_sent_at(fields.sent_at));
        }
        assert!(!is_sent_at("2026-11-20T10:41:00Z"));
        assert!(!is_sent_at("2026-11-20T10:41:00.000+09:00"));
    }
}
