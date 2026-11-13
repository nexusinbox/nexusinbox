//! The agent's own root, from the browser that made the connect code
//! (docs/40 §13.4, §13.5). `nexusinbox connect` with a long code leaves
//! the code's secret in the agent's directory; the browser MACs the
//! agent's root with it and stores the MAC on the server. The gateway
//! checks that MAC, remembers the root as its own agent's, and deletes
//! the secret. Until then it does not take its own agent's root from the
//! server alone.

use std::path::{Path, PathBuf};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;

/// Written by `nexusinbox-signer --connect` (0600).
pub const PAIRING_FILE: &str = "pairing-secret.json";

#[derive(Clone, Debug, Deserialize)]
pub struct PairingSecret {
    pub credential_id: String,
    pub aid: String,
    /// The 16 characters after the server's code, normalized.
    pub secret: String,
}

pub fn pairing_path(dir: &Path) -> PathBuf {
    dir.join(PAIRING_FILE)
}

/// The secret waiting to confirm the root, if any.
pub fn load(dir: Option<&Path>) -> Option<PairingSecret> {
    let bytes = std::fs::read(pairing_path(dir?)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn mac(secret: &str, message: &str) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC takes any key length");
    mac.update(message.as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

/// The browser's MAC over the agent's root.
pub fn root_mac(secret: &str, credential_id: &str, aid: &str, root: &str) -> String {
    mac(
        secret,
        &format!("nexusinbox-pair-root-v1\n{credential_id}\n{aid}\n{root}"),
    )
}

/// Does `got` match the root MAC for `root`? Compared without an early exit.
pub fn root_mac_matches(pairing: &PairingSecret, root: &str, got: &str) -> bool {
    let want = root_mac(&pairing.secret, &pairing.credential_id, &pairing.aid, root);
    want.len() == got.len()
        && want
            .bytes()
            .zip(got.bytes())
            .fold(0u8, |diff, (a, b)| diff | (a ^ b))
            == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    struct Vectors {
        macs: Vec<Case>,
    }

    #[derive(Deserialize)]
    struct Case {
        secret: String,
        credential_id: String,
        did: String,
        enc: String,
        aid: String,
        root: String,
        device_mac: String,
        root_mac: String,
    }

    #[test]
    fn macs_match_the_shared_vectors() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/vectors/pairing_mac.json"
        );
        let vectors: Vectors = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        for c in &vectors.macs {
            assert_eq!(
                root_mac(&c.secret, &c.credential_id, &c.aid, &c.root),
                c.root_mac
            );
            assert_eq!(
                mac(
                    &c.secret,
                    &format!(
                        "nexusinbox-pair-device-v1\n{}\n{}\n{}",
                        c.credential_id, c.did, c.enc
                    )
                ),
                c.device_mac
            );
            let pairing = PairingSecret {
                credential_id: c.credential_id.clone(),
                aid: c.aid.clone(),
                secret: c.secret.clone(),
            };
            assert!(root_mac_matches(&pairing, &c.root, &c.root_mac));
            assert!(!root_mac_matches(&pairing, "did:key:zOther", &c.root_mac));
        }
    }
}
