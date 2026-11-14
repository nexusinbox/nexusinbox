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
//! back for another root, older, or gone.
//!
//! Signers (docs/40 §17.3): a v1 list is signed by the root. A v2 list names
//! `signers`, and each version is signed by a signer of the version before,
//! so a list signed by a signer the pin does not trust yet is followed from
//! the pinned version through the history (`GET /recipients/device-lists`).

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

/// What is remembered of an agent: its root, the newest list version seen,
/// and who may sign the next one when that is not just the root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pin {
    pub root: String,
    pub version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signers: Option<Vec<String>>,
}

impl Pin {
    /// A pin for a root alone (v1 lists).
    pub fn root(root: &str, version: u64) -> Self {
        Pin {
            root: root.to_string(),
            version,
            signers: None,
        }
    }

    fn trusted(&self) -> Vec<String> {
        self.signers
            .clone()
            .unwrap_or_else(|| vec![self.root.clone()])
    }
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
    pub browser: bool,
}

/// A checked list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceList {
    pub root: String,
    pub version: u64,
    pub devices: Vec<ListDevice>,
    /// Who may sign the next version (a v1 list: its root).
    pub signers: Vec<String>,
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
        browser: kind == "browser",
    })
}

/// Read a signed list for `aid`: the header, the signature by the key it
/// names (`kid`), and the shape. Returns the list and its signer; whether
/// that signer may sign it is the caller's check.
pub fn read_device_list(jws: &str, aid: &str) -> Option<(DeviceList, String)> {
    let mut parts = jws.split('.');
    let (header_b64, payload_b64, signature_b64) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let header = json_part(header_b64)?;
    if header.get("alg")?.as_str()? != "EdDSA" || header.get("typ")?.as_str()? != DEVICE_LIST_TYP {
        return None;
    }
    let signer = header.get("kid")?.as_str()?.to_string();
    let key = VerifyingKey::from_bytes(&did_key_ed25519(&signer)?).ok()?;
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
    let v2 = payload.get("v")?.as_u64()? == 2;
    let root = payload.get("root")?.as_str()?.to_string();
    if payload.len() != if v2 { 7 } else { 6 }
        || !(v2 || payload.get("v")?.as_u64()? == 1)
        || payload.get("aid")?.as_str()? != aid
        || !root.starts_with("did:key:z")
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
    let signers = if v2 {
        // Browsers the list names, at least one, none twice.
        let named: Vec<String> = payload
            .get("signers")?
            .as_array()?
            .iter()
            .map(|v| v.as_str().map(str::to_string))
            .collect::<Option<_>>()?;
        let unique: HashSet<&str> = named.iter().map(String::as_str).collect();
        let all_browsers = named
            .iter()
            .all(|d| devices.iter().any(|x| &x.did == d && x.browser));
        if named.is_empty() || unique.len() != named.len() || !all_browsers {
            return None;
        }
        named
    } else {
        if signer != root {
            return None;
        }
        vec![root.clone()]
    };
    Some((
        DeviceList {
            root,
            version,
            devices,
            signers,
        },
        signer,
    ))
}

/// The versions after `pin` (or from version 1) up to `upto`, each signed
/// by a signer of the one before (version 1 by the root), out of
/// `history` (any versions the server returned). None if any is missing or
/// does not hold.
pub fn follow_versions(
    aid: &str,
    root: &str,
    pin: Option<&Pin>,
    upto: u64,
    history: Option<&[ListRef]>,
) -> Option<Vec<(DeviceList, String)>> {
    let history = history?;
    let after = pin.map_or(0, |p| p.version);
    if upto <= after {
        return None;
    }
    let mut allowed = pin.map_or_else(|| vec![root.to_string()], Pin::trusted);
    let mut out = Vec::new();
    for version in after + 1..=upto {
        let mut found = history.iter().filter(|r| r.version == version);
        let (Some(r), None) = (found.next(), found.next()) else {
            return None;
        };
        let (list, signer) = read_device_list(&r.jws, aid)?;
        if list.root != root || list.version != version || !allowed.contains(&signer) {
            return None;
        }
        allowed = list.signers.clone();
        out.push((list, r.jws.clone()));
    }
    Some(out)
}

/// Check an agent's current list against what is remembered (core
/// `checkDeviceList`). A list signed by a signer the pin trusts (or, seen
/// for the first time, by its root) is checked directly; any other signer
/// is followed through `history`.
pub fn check_list(
    aid: &str,
    list_ref: &ListRef,
    pin: Option<&Pin>,
    accept_root: Option<&str>,
    history: Option<&[ListRef]>,
) -> Result<DeviceList, (StopReason, Option<String>)> {
    let Some((list, signer)) = read_device_list(&list_ref.jws, aid) else {
        return Err((StopReason::Signature, None));
    };
    if list.version != list_ref.version {
        return Err((StopReason::Signature, None));
    }
    let mut pin = pin;
    if let Some(p) = pin {
        if p.root != list.root {
            if accept_root != Some(list.root.as_str()) {
                return Err((StopReason::RootChanged, Some(list.root)));
            }
            pin = None;
        }
    }
    if pin.is_some_and(|p| list.version < p.version) {
        return Err((StopReason::Rollback, None));
    }
    let trusted = pin.map_or_else(|| vec![list.root.clone()], Pin::trusted);
    if trusted.contains(&signer) {
        return Ok(list);
    }
    match follow_versions(aid, &list.root, pin, list.version, history) {
        Some(chain) if chain.last().is_some_and(|(_, jws)| *jws == list_ref.jws) => Ok(list),
        _ => Err((StopReason::Signature, None)),
    }
}

/// Whether checking `list_ref` needs the version history: it is signed by
/// a signer the pin does not trust yet (docs/40 §17.3).
pub fn needs_history(
    aid: &str,
    list_ref: &ListRef,
    pin: Option<&Pin>,
    accept_root: Option<&str>,
) -> bool {
    let Some((list, signer)) = read_device_list(&list_ref.jws, aid) else {
        return false;
    };
    let pin = match pin {
        Some(p) if p.root != list.root => {
            if accept_root != Some(list.root.as_str()) {
                return false;
            }
            None
        }
        other => other,
    };
    !pin.map_or_else(|| vec![list.root.clone()], Pin::trusted)
        .contains(&signer)
}

/// The pin to keep after `list` checked (it only moves forward).
pub fn pin_for(pin: Option<&Pin>, list: &DeviceList) -> Pin {
    if let Some(p) = pin {
        if p.root == list.root && p.version > list.version {
            return p.clone();
        }
    }
    let only_root = list.signers.len() == 1 && list.signers[0] == list.root;
    Pin {
        root: list.root.clone(),
        version: list.version,
        signers: (!only_root).then(|| list.signers.clone()),
    }
}

fn stop(reason: StopReason) -> Decision {
    Decision::Stop { reason, root: None }
}

/// Decide which devices of `served` to wrap a message's key for.
/// `requested` is what the sender asked to resolve (an AID or a DID);
/// `known_aid` the agent a requested DID was seen under before; `pin` what
/// is remembered of this agent; `accept_root` a new root the person has
/// accepted; `history` the list versions, fetched when `needs_history`.
pub fn decide(
    served: &Served,
    requested: &str,
    known_aid: Option<&str>,
    pin: Option<&Pin>,
    accept_root: Option<&str>,
    history: Option<&[ListRef]>,
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

    let list = match check_list(served.aid, list_ref, pin, accept_root, history) {
        Ok(list) => list,
        Err((reason, root)) => return Decision::Stop { reason, root },
    };

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
    Some(pin_for(pin, list))
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

/// The confirmation number two people read aloud to check each other's
/// agent (docs/40 §16.2): the same as core `confirmationNumber`
/// (tests/vectors/confirmation_number.json).
pub fn confirmation_number(root_a: &str, root_b: &str) -> String {
    use sha2::{Digest, Sha256};
    let (first, second) = if root_a <= root_b {
        (root_a, root_b)
    } else {
        (root_b, root_a)
    };
    let digest = Sha256::digest(format!("nexusinbox-confirm-v1\n{first}\n{second}").as_bytes());
    let value = digest[..9]
        .iter()
        .fold(0u128, |acc, byte| (acc << 8) | u128::from(*byte));
    let digits = format!("{:020}", value % 10u128.pow(20));
    digits
        .as_bytes()
        .chunks(5)
        .map(|c| std::str::from_utf8(c).expect("ascii digits"))
        .collect::<Vec<_>>()
        .join(" ")
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
        /// What `GET /recipients/device-lists` returns (null: nothing).
        #[serde(default)]
        history: Option<Vec<ListRef>>,
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
        assert_eq!(vectors.cases.len(), 24);
        for case in &vectors.cases {
            let served = Served {
                aid: &case.served.aid,
                did: &case.served.did,
                encryption_public_key: &case.served.encryption_public_key,
                devices: &case.served.devices,
                device_list: case.served.device_list.as_ref(),
            };
            // As the gateway does: fetch the history only when needed.
            let history = served
                .device_list
                .filter(|l| {
                    needs_history(
                        served.aid,
                        l,
                        case.pin.as_ref(),
                        case.accept_root.as_deref(),
                    )
                })
                .and(case.history.as_deref());
            let decision = decide(
                &served,
                &case.requested,
                case.known_aid.as_deref(),
                case.pin.as_ref(),
                case.accept_root.as_deref(),
                history,
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
                signers: Some(vec!["did:key:zPhone".into()]),
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

    #[test]
    fn confirmation_numbers_match_the_shared_vectors() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/vectors/confirmation_number.json"
        );
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        for c in v["cases"].as_array().unwrap() {
            let (a, b) = (c["a"].as_str().unwrap(), c["b"].as_str().unwrap());
            assert_eq!(confirmation_number(a, b), c["number"].as_str().unwrap());
            assert_eq!(confirmation_number(b, a), c["number"].as_str().unwrap());
        }
    }
}
