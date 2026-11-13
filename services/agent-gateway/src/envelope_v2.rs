//! Envelope signature v2 and checking the sender (docs/40 §14), the Rust
//! side of packages/core/src/envelope-v2.ts.
//!
//! Sending: the gateway builds the signed fields, the daemon signs them
//! (`sign_envelope_v2`, with the body and attachment metadata hashed).
//! Reading: the gateway checks a delivered message's signature, then that
//! the signing device is on the sender's device list signed by the root it
//! remembers. Shared vectors: tests/vectors/envelope_v2.json and
//! sender_check_decisions.json.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::device_trust::{self, DeviceList, ListRef, Pin};

pub const PREFIX: &str = "nexusinbox-envelope-v2\n";
/// How far ahead of this computer's clock a message may say it was sent.
const MAX_CLOCK_AHEAD_MS: i64 = 10 * 60 * 1000;
/// Automatic replies only answer messages sent within this time.
pub const AUTO_REPLY_MAX_AGE_MS: i64 = 24 * 60 * 60 * 1000;
/// From 2027-02-11T00:00:00Z every message without a v2 signature is a
/// warning (docs/40 §15.2): messages sent before stage 4 are gone by then.
pub const UNSIGNED_CUTOFF_MS: i64 = 1_802_304_000_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Wrap {
    pub did: String,
    pub key: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attachment {
    pub id: String,
    pub metadata_encrypted: String,
    pub metadata_nonce: String,
}

/// Everything a v2 signature covers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fields {
    pub sender_aid: String,
    pub sender_did: String,
    pub recipient_aid: String,
    pub recipient_did: String,
    pub sent_at: String,
    pub content_type: String,
    pub thread_id: Option<String>,
    pub subject_encrypted: String,
    pub encrypted_content: String,
    pub encrypted_key: String,
    pub nonce: String,
    pub sender_encrypted_key: Option<String>,
    pub encrypted_keys: Vec<Wrap>,
    pub sender_encrypted_keys: Vec<Wrap>,
    pub attachments: Vec<Attachment>,
}

pub fn sha256_b64(text: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(text.as_bytes()))
}

/// The time now as a v2 `sent_at`.
pub fn sent_at_now() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string()
}

fn s(value: &str) -> String {
    serde_json::to_string(value).expect("a string serializes")
}

fn opt(value: Option<&str>) -> String {
    value.map(s).unwrap_or_else(|| "null".to_string())
}

fn sorted_wraps(list: &[Wrap]) -> Vec<&Wrap> {
    let mut sorted: Vec<&Wrap> = list.iter().collect();
    sorted.sort_by(|a, b| a.did.cmp(&b.did));
    sorted
}

fn wraps(list: &[Wrap]) -> String {
    let items: Vec<String> = sorted_wraps(list)
        .iter()
        .map(|w| format!("{{\"did\":{},\"key\":{}}}", s(&w.did), s(&w.key)))
        .collect();
    format!("[{}]", items.join(","))
}

impl Fields {
    fn sorted_attachments(&self) -> Vec<&Attachment> {
        let mut sorted: Vec<&Attachment> = self.attachments.iter().collect();
        sorted.sort_by(|a, b| a.id.cmp(&b.id));
        sorted
    }

    /// The bytes a v2 signature covers, as text.
    pub fn signing_input(&self) -> String {
        let attachments: Vec<String> = self
            .sorted_attachments()
            .iter()
            .map(|a| {
                format!(
                    "{{\"id\":{},\"metadata_nonce\":{},\"metadata_sha256\":{}}}",
                    s(&a.id),
                    s(&a.metadata_nonce),
                    s(&sha256_b64(&a.metadata_encrypted))
                )
            })
            .collect();
        format!(
            "{PREFIX}{{\"attachments\":[{}],\"content_sha256\":{},\"content_type\":{},\"encrypted_key\":{},\"encrypted_keys\":{},\"nonce\":{},\"recipient_aid\":{},\"recipient_did\":{},\"sender_aid\":{},\"sender_did\":{},\"sender_encrypted_key\":{},\"sender_encrypted_keys\":{},\"sent_at\":{},\"subject_encrypted\":{},\"thread_id\":{},\"v\":2}}",
            attachments.join(","),
            s(&sha256_b64(&self.encrypted_content)),
            s(&self.content_type),
            s(&self.encrypted_key),
            wraps(&self.encrypted_keys),
            s(&self.nonce),
            s(&self.recipient_aid),
            s(&self.recipient_did),
            s(&self.sender_aid),
            s(&self.sender_did),
            opt(self.sender_encrypted_key.as_deref()),
            wraps(&self.sender_encrypted_keys),
            s(&self.sent_at),
            s(&self.subject_encrypted),
            opt(self.thread_id.as_deref()),
        )
    }

    /// What the daemon's `sign_envelope_v2` takes: the signed object with
    /// the body and attachment metadata as hashes.
    pub fn daemon_params(&self) -> Value {
        let wraps = |list: &[Wrap]| -> Vec<Value> {
            list.iter()
                .map(|w| json!({ "did": w.did, "key": w.key }))
                .collect()
        };
        json!({
            "sender_aid": self.sender_aid,
            "sender_did": self.sender_did,
            "recipient_aid": self.recipient_aid,
            "recipient_did": self.recipient_did,
            "sent_at": self.sent_at,
            "content_type": self.content_type,
            "thread_id": self.thread_id,
            "subject_encrypted": self.subject_encrypted,
            "content_sha256": sha256_b64(&self.encrypted_content),
            "encrypted_key": self.encrypted_key,
            "nonce": self.nonce,
            "sender_encrypted_key": self.sender_encrypted_key,
            "encrypted_keys": wraps(&self.encrypted_keys),
            "sender_encrypted_keys": wraps(&self.sender_encrypted_keys),
            "attachments": self.attachments.iter().map(|a| json!({
                "id": a.id,
                "metadata_nonce": a.metadata_nonce,
                "metadata_sha256": sha256_b64(&a.metadata_encrypted),
            })).collect::<Vec<_>>(),
        })
    }

    /// The `signature_v2` object a sender puts in the envelope.
    pub fn signature_json(&self, signature: &str) -> Value {
        json!({
            "signature": signature,
            "sent_at": self.sent_at,
            "sender_aid": self.sender_aid,
            "recipient_aid": self.recipient_aid,
        })
    }
}

fn wraps_of(value: &Value) -> Vec<Wrap> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|w| {
            Some(Wrap {
                did: w.get("did")?.as_str()?.to_string(),
                key: w.get("key")?.as_str()?.to_string(),
            })
        })
        .collect()
}

fn str_of(value: &Value, key: &str) -> Option<String> {
    value.get(key)?.as_str().map(str::to_string)
}

/// The fields an outgoing envelope (`POST /messages` shape: top-level
/// `encrypted_*`, `metadata.{subject_encrypted, content_type, thread_id}`)
/// signs, for the given agents and devices.
pub fn outgoing_fields(
    envelope: &Value,
    sender: (&str, &str),
    recipient: (&str, &str),
    sent_at: String,
) -> Result<Fields, String> {
    let metadata = envelope.get("metadata").unwrap_or(&Value::Null);
    let need =
        |value: Option<String>, name: &str| value.ok_or_else(|| format!("missing envelope.{name}"));
    Ok(Fields {
        sender_aid: sender.0.to_string(),
        sender_did: sender.1.to_string(),
        recipient_aid: recipient.0.to_string(),
        recipient_did: recipient.1.to_string(),
        sent_at,
        content_type: str_of(metadata, "content_type").unwrap_or_else(|| "text/plain".into()),
        thread_id: str_of(metadata, "thread_id"),
        subject_encrypted: need(
            str_of(metadata, "subject_encrypted"),
            "metadata.subject_encrypted",
        )?,
        encrypted_content: need(str_of(envelope, "encrypted_content"), "encrypted_content")?,
        encrypted_key: need(str_of(envelope, "encrypted_key"), "encrypted_key")?,
        nonce: need(str_of(envelope, "nonce"), "nonce")?,
        sender_encrypted_key: str_of(envelope, "sender_encrypted_key"),
        encrypted_keys: wraps_of(envelope.get("encrypted_keys").unwrap_or(&Value::Null)),
        sender_encrypted_keys: wraps_of(
            envelope
                .get("sender_encrypted_keys")
                .unwrap_or(&Value::Null),
        ),
        attachments: Vec::new(),
    })
}

// ---------------------------------------------------------------------------
// Checking the sender (docs/40 §14.5).

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SenderState {
    Verified,
    Unsigned,
    /// No signature from a sender seen signing before (docs/40 §15.2).
    Downgraded,
    /// No signature after UNSIGNED_CUTOFF_MS.
    MissingSignature,
    NoList,
    Altered,
    NotListed,
    RootChanged,
    Broken,
}

impl SenderState {
    pub fn code(self) -> &'static str {
        match self {
            SenderState::Verified => "verified",
            SenderState::Unsigned => "unsigned",
            SenderState::Downgraded => "downgraded",
            SenderState::MissingSignature => "missing_signature",
            SenderState::NoList => "no_list",
            SenderState::Altered => "altered",
            SenderState::NotListed => "not_listed",
            SenderState::RootChanged => "root_changed",
            SenderState::Broken => "broken",
        }
    }

    /// Whether a reader is warned (as opposed to a quiet note, or nothing).
    pub fn warns(self) -> bool {
        !matches!(
            self,
            SenderState::Verified | SenderState::Unsigned | SenderState::NoList
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SenderCheck {
    pub state: SenderState,
    /// The sender's current list, when it verified (to move the pin).
    pub list: Option<DeviceList>,
    /// The root the sender's list is now signed by, when it changed.
    pub changed_root: Option<String>,
}

impl SenderCheck {
    fn only(state: SenderState) -> Self {
        SenderCheck {
            state,
            list: None,
            changed_root: None,
        }
    }
}

/// The sender's agent as `GET /recipients/resolve` returns it.
pub struct SenderAgent<'a> {
    pub aid: &'a str,
    pub device_list: Option<&'a ListRef>,
}

/// The fields a delivered message's (`GET /messages/:id/content`) v2
/// signature should cover.
pub fn delivered_fields(content: &Value, sig: &Value) -> Option<Fields> {
    Some(Fields {
        sender_aid: str_of(sig, "sender_aid")?,
        sender_did: str_of(content, "sender_did")?,
        recipient_aid: str_of(sig, "recipient_aid")?,
        recipient_did: str_of(content, "recipient_did")?,
        sent_at: str_of(sig, "sent_at")?,
        content_type: str_of(content, "content_type").unwrap_or_else(|| "text/plain".into()),
        thread_id: str_of(content, "thread_id"),
        subject_encrypted: str_of(content, "subject_encrypted")?,
        encrypted_content: str_of(content, "encrypted_content")?,
        encrypted_key: str_of(content, "encrypted_key")?,
        nonce: str_of(content, "nonce")?,
        sender_encrypted_key: str_of(content, "sender_encrypted_key"),
        encrypted_keys: wraps_of(content.get("encrypted_keys").unwrap_or(&Value::Null)),
        sender_encrypted_keys: wraps_of(
            content.get("sender_encrypted_keys").unwrap_or(&Value::Null),
        ),
        attachments: content
            .get("attachments")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|a| {
                Some(Attachment {
                    id: str_of(a, "id")?,
                    metadata_encrypted: str_of(a, "metadata_encrypted")?,
                    metadata_nonce: str_of(a, "metadata_nonce")?,
                })
            })
            .collect(),
    })
}

/// Whether `signature` is `f.sender_did`'s signature over `f`.
pub fn verify_signature(f: &Fields, signature: &str) -> bool {
    let Some(key) = device_trust::did_key_ed25519(&f.sender_did)
        .and_then(|bytes| VerifyingKey::from_bytes(&bytes).ok())
    else {
        return false;
    };
    let Some(sig) = URL_SAFE_NO_PAD
        .decode(signature)
        .ok()
        .and_then(|bytes| <[u8; 64]>::try_from(bytes).ok())
    else {
        return false;
    };
    key.verify_strict(f.signing_input().as_bytes(), &Signature::from_bytes(&sig))
        .is_ok()
}

fn parse_ms(at: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(at)
        .ok()
        .map(|t| t.timestamp_millis())
}

/// Check who sent a delivered message (core `checkSender`). `reader_aids`
/// are the agents this computer reads for; `sender` the sender's agent
/// as resolved by `signature_v2.sender_aid`; `pin` what is remembered of
/// it; `signed_before` whether the sender's agent was seen signing with v2;
/// `now_ms` the clock.
pub fn check_sender(
    content: &Value,
    reader_aids: &[&str],
    sender: Option<SenderAgent<'_>>,
    pin: Option<&Pin>,
    signed_before: bool,
    now_ms: i64,
) -> SenderCheck {
    let Some(sig) = content.get("signature_v2").filter(|v| v.is_object()) else {
        return SenderCheck::only(if signed_before {
            SenderState::Downgraded
        } else if now_ms >= UNSIGNED_CUTOFF_MS {
            SenderState::MissingSignature
        } else {
            SenderState::Unsigned
        });
    };
    let Some(fields) = delivered_fields(content, sig) else {
        return SenderCheck::only(SenderState::Altered);
    };
    if !reader_aids.contains(&fields.sender_aid.as_str())
        && !reader_aids.contains(&fields.recipient_aid.as_str())
    {
        return SenderCheck::only(SenderState::Altered);
    }
    match parse_ms(&fields.sent_at) {
        Some(at) if at <= now_ms + MAX_CLOCK_AHEAD_MS => {}
        _ => return SenderCheck::only(SenderState::Altered),
    }
    let signature = sig.get("signature").and_then(Value::as_str).unwrap_or("");
    if !verify_signature(&fields, signature) {
        return SenderCheck::only(SenderState::Altered);
    }

    if sender.as_ref().is_some_and(|s| s.aid != fields.sender_aid) {
        return SenderCheck::only(SenderState::Altered);
    }
    let Some(list_ref) = sender.and_then(|s| s.device_list) else {
        return SenderCheck::only(if pin.is_some() {
            SenderState::Broken
        } else {
            SenderState::NoList
        });
    };
    let list = device_trust::list_root(&list_ref.jws).and_then(|root| {
        device_trust::verify_device_list(&list_ref.jws, &fields.sender_aid, &root)
    });
    let Some(list) = list.filter(|l| l.version == list_ref.version) else {
        return SenderCheck::only(SenderState::Broken);
    };
    if let Some(pin) = pin {
        if pin.root != list.root {
            return SenderCheck {
                state: SenderState::RootChanged,
                list: None,
                changed_root: Some(list.root),
            };
        }
        if list.version < pin.version {
            return SenderCheck::only(SenderState::Broken);
        }
    }

    // The list as it was when the message was sent: same root, not newer.
    let sent_ref: Option<ListRef> = content
        .get("sender_device_list")
        .filter(|v| v.is_object())
        .and_then(|v| serde_json::from_value(v.clone()).ok());
    let sent_with = match sent_ref {
        Some(r) if r.version != list.version => {
            match device_trust::verify_device_list(&r.jws, &fields.sender_aid, &list.root) {
                Some(old) if old.version == r.version && old.version <= list.version => old,
                _ => {
                    return SenderCheck {
                        state: SenderState::Broken,
                        list: Some(list),
                        changed_root: None,
                    }
                }
            }
        }
        _ => list.clone(),
    };
    let state = if sent_with.devices.iter().any(|d| d.did == fields.sender_did) {
        SenderState::Verified
    } else {
        SenderState::NotListed
    };
    SenderCheck {
        state,
        list: Some(list),
        changed_root: None,
    }
}

/// What to remember after a check (the pin only moves forward).
pub fn pin_after_check(pin: Option<&Pin>, check: &SenderCheck) -> Option<Pin> {
    let Some(list) = check.list.as_ref() else {
        return pin.cloned();
    };
    match pin {
        Some(p) if p.root == list.root => Some(Pin {
            root: list.root.clone(),
            version: p.version.max(list.version),
        }),
        _ => Some(Pin {
            root: list.root.clone(),
            version: list.version,
        }),
    }
}

/// None when an automatic reply may answer; otherwise the reason recorded.
pub fn auto_reply_block(
    state: SenderState,
    sent_at: Option<&str>,
    now_ms: i64,
) -> Option<&'static str> {
    match state {
        SenderState::Verified => match sent_at.and_then(parse_ms) {
            Some(at) if now_ms - at <= AUTO_REPLY_MAX_AGE_MS => None,
            _ => Some("stale"),
        },
        SenderState::Unsigned | SenderState::NoList => Some("unsigned"),
        SenderState::Altered | SenderState::Downgraded | SenderState::MissingSignature => {
            Some("altered")
        }
        SenderState::NotListed => Some("not_listed"),
        SenderState::RootChanged => Some("root_changed"),
        SenderState::Broken => Some("signature"),
    }
}

// ---------------------------------------------------------------------------
// Messages already answered (docs/40 §14.5). The server can deliver the same
// signed message again under a new id; an automatic reply goes to it once.

pub const ANSWERED_FILE: &str = "answered.json";
/// Longer than AUTO_REPLY_MAX_AGE_MS: after that the message is too old anyway.
const ANSWERED_KEEP_MS: i64 = 25 * 60 * 60 * 1000;

/// Hashes of the v2 signatures replied to, with when they may be forgotten.
pub struct AnsweredStore {
    path: Option<std::path::PathBuf>,
    /// Without a directory (settings given by hand), kept for this run only.
    memory: std::sync::Mutex<std::collections::BTreeMap<String, i64>>,
}

impl AnsweredStore {
    pub fn new(dir: Option<&std::path::Path>) -> Self {
        Self {
            path: dir.map(|d| d.join(ANSWERED_FILE)),
            memory: std::sync::Mutex::new(Default::default()),
        }
    }

    fn load(&self) -> std::collections::BTreeMap<String, i64> {
        match &self.path {
            None => self.memory.lock().unwrap().clone(),
            Some(path) => std::fs::read(path)
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                .unwrap_or_default(),
        }
    }

    pub fn contains(&self, signature: &str, now_ms: i64) -> bool {
        self.load()
            .get(&sha256_b64(signature))
            .is_some_and(|until| *until > now_ms)
    }

    pub fn remember(&self, signature: &str, now_ms: i64) -> Result<(), String> {
        let mut map = self.load();
        map.retain(|_, until| *until > now_ms);
        map.insert(sha256_b64(signature), now_ms + ANSWERED_KEEP_MS);
        let Some(path) = &self.path else {
            *self.memory.lock().unwrap() = map;
            return Ok(());
        };
        let tmp = path.with_extension("json.tmp");
        let bytes = serde_json::to_vec(&map).map_err(|e| e.to_string())?;
        device_trust::write_private(&tmp, &bytes)
            .map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, path).map_err(|e| format!("cannot replace {}: {e}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vectors(name: &str) -> Value {
        let path = format!("{}/../../tests/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    #[test]
    fn signing_matches_the_shared_vectors() {
        let v = vectors("envelope_v2.json");
        for c in v["cases"].as_array().unwrap() {
            let f = &c["fields"];
            let fields = Fields {
                sender_aid: str_of(f, "sender_aid").unwrap(),
                sender_did: str_of(f, "sender_did").unwrap(),
                recipient_aid: str_of(f, "recipient_aid").unwrap(),
                recipient_did: str_of(f, "recipient_did").unwrap(),
                sent_at: str_of(f, "sent_at").unwrap(),
                content_type: str_of(f, "content_type").unwrap(),
                thread_id: str_of(f, "thread_id"),
                subject_encrypted: str_of(f, "subject_encrypted").unwrap(),
                encrypted_content: str_of(f, "encrypted_content").unwrap(),
                encrypted_key: str_of(f, "encrypted_key").unwrap(),
                nonce: str_of(f, "nonce").unwrap(),
                sender_encrypted_key: str_of(f, "sender_encrypted_key"),
                encrypted_keys: wraps_of(&f["encrypted_keys"]),
                sender_encrypted_keys: wraps_of(&f["sender_encrypted_keys"]),
                attachments: f["attachments"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|a| Attachment {
                        id: str_of(a, "id").unwrap(),
                        metadata_encrypted: str_of(a, "metadata_encrypted").unwrap(),
                        metadata_nonce: str_of(a, "metadata_nonce").unwrap(),
                    })
                    .collect(),
            };
            assert_eq!(fields.signing_input(), c["signing_input"].as_str().unwrap());
            assert!(verify_signature(&fields, c["signature"].as_str().unwrap()));
            let mut changed = fields.clone();
            changed.content_type = "text/other".into();
            assert!(!verify_signature(
                &changed,
                c["signature"].as_str().unwrap()
            ));
            // The daemon's form names the same values, hashed.
            let p = fields.daemon_params();
            assert_eq!(p["content_sha256"], sha256_b64(&fields.encrypted_content));
            assert_eq!(p["sender_aid"], fields.sender_aid.as_str());
        }
    }

    #[test]
    fn sender_checks_match_the_shared_vectors() {
        let v = vectors("sender_check_decisions.json");
        let now = parse_ms(v["now"].as_str().unwrap()).unwrap();
        for c in v["cases"].as_array().unwrap() {
            let name = c["name"].as_str().unwrap();
            let readers: Vec<&str> = c["reader_aids"]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| a.as_str().unwrap())
                .collect();
            let list_ref: Option<ListRef> = c["sender"]
                .get("device_list")
                .filter(|v| v.is_object())
                .map(|v| serde_json::from_value(v.clone()).unwrap());
            let sender = c["sender"].as_object().map(|s| SenderAgent {
                aid: s["aid"].as_str().unwrap(),
                device_list: list_ref.as_ref(),
            });
            let pin: Option<Pin> = serde_json::from_value(c["pin"].clone()).unwrap();
            let case_now = c["now"].as_str().and_then(parse_ms).unwrap_or(now);
            let signed_before = c["signed_before"].as_bool().unwrap_or(false);
            let check = check_sender(
                &c["content"],
                &readers,
                sender,
                pin.as_ref(),
                signed_before,
                case_now,
            );
            assert_eq!(
                check.state.code(),
                c["expected"]["state"].as_str().unwrap(),
                "{name}"
            );
            let after: Option<Pin> =
                serde_json::from_value(c["expected"]["pin_after"].clone()).unwrap();
            assert_eq!(pin_after_check(pin.as_ref(), &check), after, "{name}");
        }
        for c in v["auto_reply"].as_array().unwrap() {
            let state = match c["state"].as_str().unwrap() {
                "verified" => SenderState::Verified,
                "unsigned" => SenderState::Unsigned,
                "no_list" => SenderState::NoList,
                "altered" => SenderState::Altered,
                "not_listed" => SenderState::NotListed,
                "root_changed" => SenderState::RootChanged,
                "downgraded" => SenderState::Downgraded,
                "missing_signature" => SenderState::MissingSignature,
                _ => SenderState::Broken,
            };
            assert_eq!(
                auto_reply_block(state, c["sent_at"].as_str(), now),
                c["expected"].as_str(),
                "{}",
                c["name"]
            );
        }
    }

    #[test]
    fn an_answered_message_is_remembered_for_a_day() {
        let dir = std::env::temp_dir().join(format!("nx-answered-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = AnsweredStore::new(Some(&dir));
        let now = 1_000_000_000_000;
        assert!(!store.contains("sig-a", now));
        store.remember("sig-a", now).unwrap();
        assert!(store.contains("sig-a", now + 1));
        assert!(!store.contains("sig-b", now + 1));
        // A new store reads the file, and forgets after 25 hours.
        let again = AnsweredStore::new(Some(&dir));
        assert!(again.contains("sig-a", now + 24 * 60 * 60 * 1000));
        assert!(!again.contains("sig-a", now + ANSWERED_KEEP_MS + 1));
        let raw = std::fs::read_to_string(dir.join(ANSWERED_FILE)).unwrap();
        assert!(!raw.contains("sig-a"), "only hashes are kept");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
