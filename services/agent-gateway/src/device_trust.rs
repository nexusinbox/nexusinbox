//! Checking a recipient's signed device list before wrapping a message key
//! for it (docs/40 §12.3, §13.2). The rules are packages/core
//! `decideWrapTargets`, and both pass tests/vectors/device_list_decisions.json.
//!
//! An agent's root key (the browser key it was created with) signs the
//! list of devices that may read its messages. The server stores the list
//! but cannot sign one, so wrapping only for listed devices it still
//! returns, with the listed keys, keeps it from adding a device or swapping
//! a key. The gateway remembers each agent's root and the newest version
//! seen (`peers.json` in the agent's directory) and stops when a list comes
//! back signed by another root, older, or gone.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

pub const DEVICE_LIST_TYP: &str = "nexusinbox-device-list";
/// Most devices one list may name (the server's wrap limit).
pub const MAX_LIST_DEVICES: usize = 10;
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// What is remembered of an agent: its root and the newest list version seen.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pin {
    pub root: String,
    pub version: u64,
}

/// `device_list` as `GET /recipients/resolve` returns it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListRef {
    pub version: u64,
    pub jws: String,
}

/// A device to wrap for, with the key to wrap with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    pub did: String,
    pub encryption_public_key: String,
}

/// The part of a resolved agent the decision reads.
pub struct Served<'a> {
    pub aid: &'a str,
    /// The device `encrypted_key` used to be wrapped for (the newest one).
    pub did: &'a str,
    pub encryption_public_key: &'a str,
    pub devices: &'a [Target],
    pub device_list: Option<&'a ListRef>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopReason {
    /// Signed by a root other than the remembered one.
    RootChanged,
    /// Does not verify, or is for another agent than the one asked for.
    Signature,
    /// Older than one seen before.
    Rollback,
    /// There was a list before and now there is none.
    Removed,
    /// The agent has no list yet: not sent to until it makes one (docs/40 §15.2).
    NoList,
    /// None of the listed devices is still active.
    NoDevice,
}

impl StopReason {
    /// The code the API and the web use for it.
    pub fn code(self) -> &'static str {
        match self {
            StopReason::RootChanged => "root_changed",
            StopReason::Signature => "signature",
            StopReason::Rollback => "rollback",
            StopReason::Removed => "removed",
            StopReason::NoList => "no_list",
            StopReason::NoDevice => "no_device",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListDevice {
    pub did: String,
    pub enc: String,
}

/// A checked list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceList {
    pub root: String,
    pub version: u64,
    pub devices: Vec<ListDevice>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Checked: wrap for `targets`; `single` is the one `encrypted_key` goes to.
    Listed {
        list: DeviceList,
        targets: Vec<Target>,
        single: Target,
    },
    Stop {
        reason: StopReason,
        /// For `RootChanged`: the root the list is now signed by.
        root: Option<String>,
    },
}

/// The Ed25519 key a `did:key` names.
pub fn did_key_ed25519(did: &str) -> Option<[u8; 32]> {
    let encoded = did.strip_prefix("did:key:z")?;
    let decoded = bs58::decode(encoded).into_vec().ok()?;
    if decoded.len() != 34 || decoded[0] != 0xed || decoded[1] != 0x01 {
        return None;
    }
    decoded[2..].try_into().ok()
}

fn json_part(part: &str) -> Option<serde_json::Map<String, serde_json::Value>> {
    let bytes = URL_SAFE_NO_PAD.decode(part).ok()?;
    match serde_json::from_slice(&bytes).ok()? {
        serde_json::Value::Object(map) => Some(map),
        _ => None,
    }
}

/// The root a list's header names (`kid`), unchecked.
pub fn list_root(jws: &str) -> Option<String> {
    let header = json_part(jws.split('.').next()?)?;
    header.get("kid")?.as_str().map(str::to_string)
}

fn list_device(value: &serde_json::Value) -> Option<ListDevice> {
    let d = value.as_object()?;
    if d.len() != 3 {
        return None;
    }
    let did = d.get("did")?.as_str()?;
    let enc = d.get("enc")?.as_str()?;
    let kind = d.get("kind")?.as_str()?;
    if !did.starts_with("did:key:z") || enc.is_empty() {
        return None;
    }
    if !matches!(kind, "browser" | "computer" | "other") {
        return None;
    }
    Some(ListDevice {
        did: did.to_string(),
        enc: enc.to_string(),
    })
}

/// Check a signed list against the agent and the root the caller trusts.
/// Version ordering is the caller's check.
pub fn verify_device_list(jws: &str, aid: &str, root: &str) -> Option<DeviceList> {
    let mut parts = jws.split('.');
    let (header_b64, payload_b64, signature_b64) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let header = json_part(header_b64)?;
    if header.get("alg")?.as_str()? != "EdDSA"
        || header.get("typ")?.as_str()? != DEVICE_LIST_TYP
        || header.get("kid")?.as_str()? != root
    {
        return None;
    }
    let key = VerifyingKey::from_bytes(&did_key_ed25519(root)?).ok()?;
    let signature: [u8; 64] = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .ok()?
        .try_into()
        .ok()?;
    key.verify_strict(
        format!("{header_b64}.{payload_b64}").as_bytes(),
        &Signature::from_bytes(&signature),
    )
    .ok()?;

    let payload = json_part(payload_b64)?;
    if payload.len() != 6
        || payload.get("v")?.as_u64()? != 1
        || payload.get("aid")?.as_str()? != aid
        || payload.get("root")?.as_str()? != root
        || !payload.get("issued_at")?.is_string()
    {
        return None;
    }
    let version = payload.get("version")?.as_u64()?;
    if !(1..=MAX_SAFE_INTEGER).contains(&version) {
        return None;
    }
    let items = payload.get("devices")?.as_array()?;
    if items.is_empty() || items.len() > MAX_LIST_DEVICES {
        return None;
    }
    let devices: Vec<ListDevice> = items.iter().map(list_device).collect::<Option<_>>()?;
    let dids: HashSet<&str> = devices.iter().map(|d| d.did.as_str()).collect();
    if dids.len() != devices.len() {
        return None;
    }
    Some(DeviceList {
        root: root.to_string(),
        version,
        devices,
    })
}

fn stop(reason: StopReason) -> Decision {
    Decision::Stop { reason, root: None }
}

/// Decide which devices of `served` to wrap a message's key for.
/// `requested` is what the sender asked to resolve (an AID or a DID);
/// `known_aid` the agent a requested DID was seen under before; `pin` what
/// is remembered of this agent; `accept_root` a new root the person has
/// accepted.
pub fn decide(
    served: &Served,
    requested: &str,
    known_aid: Option<&str>,
    pin: Option<&Pin>,
    accept_root: Option<&str>,
) -> Decision {
    // A DID belongs to one agent for good: the server may not move it.
    if requested.starts_with("aid:") && requested != served.aid {
        return stop(StopReason::Signature);
    }
    if known_aid.is_some_and(|aid| aid != served.aid) {
        return stop(StopReason::Signature);
    }
    let served_single = Target {
        did: served.did.to_string(),
        encryption_public_key: served.encryption_public_key.to_string(),
    };
    let active: Vec<Target> = if served.devices.is_empty() {
        vec![served_single.clone()]
    } else {
        served.devices.to_vec()
    };

    let Some(list_ref) = served.device_list else {
        return stop(if pin.is_some() {
            StopReason::Removed
        } else {
            StopReason::NoList
        });
    };

    let Some(list) = list_root(&list_ref.jws)
        .and_then(|root| verify_device_list(&list_ref.jws, served.aid, &root))
    else {
        return stop(StopReason::Signature);
    };
    if list.version != list_ref.version {
        return stop(StopReason::Signature);
    }

    if let Some(pin) = pin {
        if pin.root != list.root {
            if accept_root != Some(list.root.as_str()) {
                return Decision::Stop {
                    reason: StopReason::RootChanged,
                    root: Some(list.root),
                };
            }
        } else if list.version < pin.version {
            return stop(StopReason::Rollback);
        }
    }

    let active_dids: HashSet<&str> = active.iter().map(|d| d.did.as_str()).collect();
    let targets: Vec<Target> = list
        .devices
        .iter()
        .filter(|d| active_dids.contains(d.did.as_str()))
        .map(|d| Target {
            did: d.did.clone(),
            encryption_public_key: d.enc.clone(),
        })
        .collect();
    let Some(first) = targets.first() else {
        return stop(StopReason::NoDevice);
    };
    let single = targets
        .iter()
        .find(|d| d.did == served.did)
        .or_else(|| targets.iter().find(|d| d.did == list.root))
        .unwrap_or(first)
        .clone();
    Decision::Listed {
        list,
        targets,
        single,
    }
}

/// What to remember after a decision (the pin only moves forward).
pub fn pin_after(pin: Option<&Pin>, decision: &Decision) -> Option<Pin> {
    let Decision::Listed { list, .. } = decision else {
        return pin.cloned();
    };
    match pin {
        Some(pin) if pin.root == list.root => Some(Pin {
            root: list.root.clone(),
            version: pin.version.max(list.version),
        }),
        _ => Some(Pin {
            root: list.root.clone(),
            version: list.version,
        }),
    }
}

// ---------------------------------------------------------------------------
// What this computer remembers (docs/40 §13.2): peers.json in the agent's
// directory, 0600, replaced through a temporary file. Read on every check,
// so `nexusinbox trust` can change it while the gateway runs.

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peers {
    /// Each agent's root and newest list version seen, by AID.
    #[serde(default)]
    pub pins: BTreeMap<String, Pin>,
    /// The agent each DID was seen under.
    #[serde(default)]
    pub dids: BTreeMap<String, String>,
    /// A root a list was signed by when it differed from the pin, by AID,
    /// for `nexusinbox trust` to show and accept.
    #[serde(default)]
    pub changed: BTreeMap<String, String>,
    /// Agents seen signing with v2: a message from them without a signature
    /// is a warning (docs/40 §15.2).
    #[serde(default)]
    pub signed: std::collections::BTreeSet<String>,
}

pub struct PeerStore {
    path: Option<PathBuf>,
    /// Without a directory (settings given by hand), kept for this run only.
    memory: Mutex<Peers>,
}

pub const PEERS_FILE: &str = "peers.json";

impl PeerStore {
    pub fn new(dir: Option<&Path>) -> Self {
        Self {
            path: dir.map(|d| d.join(PEERS_FILE)),
            memory: Mutex::new(Peers::default()),
        }
    }

    pub fn load(&self) -> Result<Peers, String> {
        let Some(path) = &self.path else {
            return Ok(self.memory.lock().unwrap().clone());
        };
        match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| format!("{} is not valid: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Peers::default()),
            Err(e) => Err(format!("cannot read {}: {e}", path.display())),
        }
    }

    pub fn save(&self, peers: &Peers) -> Result<(), String> {
        let Some(path) = &self.path else {
            *self.memory.lock().unwrap() = peers.clone();
            return Ok(());
        };
        let tmp = path.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(peers).map_err(|e| e.to_string())?;
        write_private(&tmp, &bytes).map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, path).map_err(|e| format!("cannot replace {}: {e}", path.display()))
    }
}

/// Write `bytes` to a new file only the owner can read.
pub fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let _ = std::fs::remove_file(path);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    struct Vectors {
        cases: Vec<Case>,
    }

    #[derive(Deserialize)]
    struct Case {
        name: String,
        served: ServedJson,
        requested: String,
        #[serde(default, rename = "knownAid")]
        known_aid: Option<String>,
        pin: Option<Pin>,
        #[serde(default, rename = "acceptRoot")]
        accept_root: Option<String>,
        expect: serde_json::Value,
    }

    #[derive(Deserialize)]
    struct ServedJson {
        aid: String,
        did: String,
        encryption_public_key: String,
        #[serde(default)]
        devices: Vec<Target>,
        device_list: Option<ListRef>,
    }

    fn expected(decision: &Decision, pin: Option<&Pin>) -> serde_json::Value {
        match decision {
            Decision::Stop { reason, root } => {
                let mut v = serde_json::json!({ "kind": "stop", "reason": reason.code() });
                if let Some(root) = root {
                    v["root"] = serde_json::json!(root);
                }
                v
            }
            Decision::Listed {
                targets, single, ..
            } => serde_json::json!({
                "kind": "listed",
                "targets": targets,
                "single": single,
                "pin": pin_after(pin, decision),
            }),
        }
    }

    #[test]
    fn decisions_match_the_shared_vectors() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/vectors/device_list_decisions.json"
        );
        let vectors: Vectors = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(vectors.cases.len(), 17);
        for case in &vectors.cases {
            let served = Served {
                aid: &case.served.aid,
                did: &case.served.did,
                encryption_public_key: &case.served.encryption_public_key,
                devices: &case.served.devices,
                device_list: case.served.device_list.as_ref(),
            };
            let decision = decide(
                &served,
                &case.requested,
                case.known_aid.as_deref(),
                case.pin.as_ref(),
                case.accept_root.as_deref(),
            );
            assert_eq!(
                expected(&decision, case.pin.as_ref()),
                case.expect,
                "{}",
                case.name
            );
        }
    }

    #[test]
    fn did_keys_decode() {
        assert!(
            did_key_ed25519("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").is_some()
        );
        assert!(did_key_ed25519("did:key:zNotBase58!").is_none());
        assert!(did_key_ed25519("did:web:example.com").is_none());
    }

    #[test]
    fn the_store_writes_a_private_file_and_reads_it_back() {
        let dir = std::env::temp_dir().join(format!("peers-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = PeerStore::new(Some(&dir));
        assert_eq!(store.load().unwrap(), Peers::default());
        let mut peers = Peers::default();
        peers.pins.insert(
            "aid:ai:x".into(),
            Pin {
                root: "did:key:zRoot".into(),
                version: 3,
            },
        );
        store.save(&peers).unwrap();
        assert_eq!(store.load().unwrap(), peers);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(dir.join(PEERS_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
