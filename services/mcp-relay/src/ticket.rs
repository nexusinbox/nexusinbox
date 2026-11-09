//! Checks the ticket a computer presents on its control connection
//! (docs/33 §11.3). The API signs the ticket; it names one MCP host and the
//! thumbprint of the computer's DPoP key. The computer adds a proof signed
//! with that key over this connection's TLS exporter value, so a ticket
//! copied elsewhere is useless.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-nexusinbox-relay";
const TICKET_TYP: &str = "nexusinbox-relay-ticket+jwt";
const PROOF_TYP: &str = "nexusinbox-relay-proof+jwt";
const MAX_TICKET_LIFETIME: u64 = 300;
const CLOCK_SKEW: u64 = 60;

pub struct Rules<'a> {
    pub api_key: &'a VerifyingKey,
    pub relay_host: &'a str,
    pub mcp_domain: &'a str,
}

/// Returns the MCP host the computer may serve.
pub fn check(
    rules: &Rules<'_>,
    ticket: &str,
    proof: &str,
    exporter: &[u8],
    now: u64,
) -> Result<String, &'static str> {
    let (header, claims) = verify_jws(ticket, rules.api_key)?;
    if header["typ"] != TICKET_TYP {
        return Err("not a relay ticket");
    }
    if claims["aud"] != rules.relay_host {
        return Err("ticket is for another relay");
    }
    let iat = claims["iat"].as_u64().ok_or("ticket has no iat")?;
    let exp = claims["exp"].as_u64().ok_or("ticket has no exp")?;
    if exp <= now || iat > now + CLOCK_SKEW || exp.saturating_sub(iat) > MAX_TICKET_LIFETIME {
        return Err("ticket expired or not yet valid");
    }
    let host = claims["sub"].as_str().ok_or("ticket has no host")?;
    if !is_mcp_host(host, rules.mcp_domain) {
        return Err("ticket names a host outside the MCP domain");
    }
    let jkt = claims["cnf"]["jkt"]
        .as_str()
        .ok_or("ticket is not key-bound")?;

    // The proof: signed by the DPoP key the ticket is bound to.
    let (proof_header, proof_claims) = verify_jws_with_embedded_key(proof, jkt)?;
    if proof_header["typ"] != PROOF_TYP {
        return Err("not a relay proof");
    }
    if proof_claims["aud"] != rules.relay_host {
        return Err("proof is for another relay");
    }
    let proof_iat = proof_claims["iat"].as_u64().ok_or("proof has no iat")?;
    if proof_iat + CLOCK_SKEW < now || proof_iat > now + CLOCK_SKEW {
        return Err("proof is stale");
    }
    let bound = proof_claims["tls"]
        .as_str()
        .ok_or("proof has no tls binding")?;
    let bound = URL_SAFE_NO_PAD
        .decode(bound)
        .map_err(|_| "proof tls binding is not base64url")?;
    if !constant_time_eq(&bound, exporter) {
        return Err("proof is for another connection");
    }
    Ok(host.to_string())
}

/// `<10 chars>.<mcp domain>`, using the alphabet the API assigns from.
pub fn is_mcp_host(host: &str, mcp_domain: &str) -> bool {
    let Some(id) = host
        .strip_suffix(mcp_domain)
        .and_then(|rest| rest.strip_suffix('.'))
    else {
        return false;
    };
    id.len() == 10
        && id
            .bytes()
            .all(|b| b"abcdefghijkmnpqrstuvwxyz23456789".contains(&b))
}

/// RFC 7638 thumbprint of an Ed25519 public key.
pub fn jwk_thumbprint(x: &str) -> String {
    let canonical = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#);
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

fn split(jws: &str) -> Result<(&str, &str, Vec<u8>), &'static str> {
    let mut parts = jws.split('.');
    let (Some(h), Some(c), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err("not a compact JWS");
    };
    let sig = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| "bad signature encoding")?;
    Ok((h, c, sig))
}

fn decode_json(part: &str) -> Result<Value, &'static str> {
    let bytes = URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_| "bad JWS encoding")?;
    serde_json::from_slice(&bytes).map_err(|_| "bad JWS JSON")
}

fn verify_with(key: &VerifyingKey, h: &str, c: &str, sig: &[u8]) -> Result<(), &'static str> {
    let sig: [u8; 64] = sig.try_into().map_err(|_| "bad signature length")?;
    key.verify_strict(format!("{h}.{c}").as_bytes(), &Signature::from_bytes(&sig))
        .map_err(|_| "signature does not verify")
}

fn verify_jws(jws: &str, key: &VerifyingKey) -> Result<(Value, Value), &'static str> {
    let (h, c, sig) = split(jws)?;
    let header = decode_json(h)?;
    if header["alg"] != "EdDSA" {
        return Err("unsupported alg");
    }
    verify_with(key, h, c, &sig)?;
    Ok((header, decode_json(c)?))
}

fn verify_jws_with_embedded_key(jws: &str, jkt: &str) -> Result<(Value, Value), &'static str> {
    let (h, c, sig) = split(jws)?;
    let header = decode_json(h)?;
    if header["alg"] != "EdDSA"
        || header["jwk"]["kty"] != "OKP"
        || header["jwk"]["crv"] != "Ed25519"
    {
        return Err("proof key must be Ed25519");
    }
    let x = header["jwk"]["x"].as_str().ok_or("proof key has no x")?;
    if !constant_time_eq(jwk_thumbprint(x).as_bytes(), jkt.as_bytes()) {
        return Err("proof key is not the one the ticket is bound to");
    }
    let raw: [u8; 32] = URL_SAFE_NO_PAD
        .decode(x)
        .map_err(|_| "bad proof key encoding")?
        .try_into()
        .map_err(|_| "bad proof key length")?;
    let key = VerifyingKey::from_bytes(&raw).map_err(|_| "bad proof key")?;
    verify_with(&key, h, c, &sig)?;
    Ok((header, decode_json(c)?))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    const HOST: &str = "k3x9q7abcd.mcp.agent-inbox.ai";
    const NOW: u64 = 1_800_000_000;

    fn jws(key: &SigningKey, header: Value, claims: Value) -> String {
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let sig = key.sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
    }

    fn x_of(key: &SigningKey) -> String {
        URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes())
    }

    fn ticket(api: &SigningKey, dpop: &SigningKey, sub: &str, iat: u64, exp: u64) -> String {
        jws(
            api,
            json!({"alg": "EdDSA", "typ": TICKET_TYP}),
            json!({"aud": "relay.agent-inbox.ai", "sub": sub,
                   "cnf": {"jkt": jwk_thumbprint(&x_of(dpop))}, "iat": iat, "exp": exp}),
        )
    }

    fn proof(dpop: &SigningKey, exporter: &[u8], iat: u64) -> String {
        jws(
            dpop,
            json!({"alg": "EdDSA", "typ": PROOF_TYP,
                   "jwk": {"kty": "OKP", "crv": "Ed25519", "x": x_of(dpop)}}),
            json!({"aud": "relay.agent-inbox.ai", "tls": URL_SAFE_NO_PAD.encode(exporter), "iat": iat}),
        )
    }

    struct Keys {
        api: SigningKey,
        dpop: SigningKey,
        api_vk: VerifyingKey,
    }

    fn keys() -> Keys {
        let api = SigningKey::from_bytes(&[1; 32]);
        Keys {
            api_vk: api.verifying_key(),
            api,
            dpop: SigningKey::from_bytes(&[2; 32]),
        }
    }

    fn rules(k: &Keys) -> Rules<'_> {
        Rules {
            api_key: &k.api_vk,
            relay_host: "relay.agent-inbox.ai",
            mcp_domain: "mcp.agent-inbox.ai",
        }
    }

    #[test]
    fn a_good_ticket_and_proof_give_the_host() {
        let k = keys();
        let t = ticket(&k.api, &k.dpop, HOST, NOW, NOW + 120);
        let p = proof(&k.dpop, &[7; 32], NOW);
        assert_eq!(check(&rules(&k), &t, &p, &[7; 32], NOW + 5).unwrap(), HOST);
    }

    #[test]
    fn a_ticket_moved_to_another_connection_fails() {
        let k = keys();
        let t = ticket(&k.api, &k.dpop, HOST, NOW, NOW + 120);
        let p = proof(&k.dpop, &[7; 32], NOW);
        assert!(check(&rules(&k), &t, &p, &[8; 32], NOW).is_err());
    }

    #[test]
    fn a_proof_from_another_key_fails() {
        let k = keys();
        let other = SigningKey::from_bytes(&[3; 32]);
        let t = ticket(&k.api, &k.dpop, HOST, NOW, NOW + 120);
        let p = proof(&other, &[7; 32], NOW);
        assert!(check(&rules(&k), &t, &p, &[7; 32], NOW).is_err());
    }

    #[test]
    fn a_ticket_not_from_the_api_fails() {
        let k = keys();
        let forged = ticket(&k.dpop, &k.dpop, HOST, NOW, NOW + 120);
        let p = proof(&k.dpop, &[7; 32], NOW);
        assert!(check(&rules(&k), &forged, &p, &[7; 32], NOW).is_err());
    }

    #[test]
    fn expired_long_lived_or_foreign_tickets_fail() {
        let k = keys();
        let p = proof(&k.dpop, &[7; 32], NOW);
        for t in [
            ticket(&k.api, &k.dpop, HOST, NOW - 200, NOW - 1),
            ticket(&k.api, &k.dpop, HOST, NOW, NOW + 3600),
            ticket(&k.api, &k.dpop, "relay.agent-inbox.ai", NOW, NOW + 120),
            ticket(
                &k.api,
                &k.dpop,
                "k3x9q7abcd.mcp.nexusinbox.ai",
                NOW,
                NOW + 120,
            ),
            ticket(
                &k.api,
                &k.dpop,
                "k3x9q7ab.mcp.agent-inbox.ai",
                NOW,
                NOW + 120,
            ),
        ] {
            assert!(check(&rules(&k), &t, &p, &[7; 32], NOW).is_err());
        }
    }

    #[test]
    fn a_stale_proof_fails() {
        let k = keys();
        let t = ticket(&k.api, &k.dpop, HOST, NOW, NOW + 120);
        let p = proof(&k.dpop, &[7; 32], NOW - 600);
        assert!(check(&rules(&k), &t, &p, &[7; 32], NOW).is_err());
    }

    #[test]
    fn mcp_hosts() {
        assert!(is_mcp_host(HOST, "mcp.agent-inbox.ai"));
        assert!(!is_mcp_host(
            "k3x9q7abcdmcp.agent-inbox.ai",
            "mcp.agent-inbox.ai"
        ));
        assert!(!is_mcp_host(
            "a.k3x9q7abcd.mcp.agent-inbox.ai",
            "mcp.agent-inbox.ai"
        ));
        assert!(!is_mcp_host(
            "k3x9q7abc1.mcp.agent-inbox.ai",
            "mcp.agent-inbox.ai"
        ));
    }
}
