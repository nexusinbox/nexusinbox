/**
 * Pairing secrets (docs/40 §13.5), browser-safe.
 *
 * The connect code a browser shows is the server's 10-character pairing
 * code followed by 16 characters only the browser and the computer know
 * (80 bits). The computer sends only the first part to the server. With
 * the second part it MACs its own keys when it activates, so the browser
 * can tell that the keys the server shows are the ones of the computer the
 * person typed the code on; the browser MACs the agent's root back, so the
 * computer learns the root it must trust.
 *
 *   device: HMAC-SHA256(secret, "nexusinbox-pair-device-v1\n" + credential_id + "\n" + did + "\n" + enc)
 *   root:   HMAC-SHA256(secret, "nexusinbox-pair-root-v1\n" + credential_id + "\n" + aid + "\n" + root)
 *
 * The key is the secret's 16 normalized characters as ASCII; MACs are
 * base64url without padding. services/signer-daemon and
 * services/agent-gateway compute the same (tests/vectors/pairing_mac.json).
 */

/** Crockford base32, as the server's pairing codes: no I, L, O or U. */
export const PAIRING_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
export const PAIRING_CODE_LEN = 10;
export const PAIRING_SECRET_LEN = 16;

/** Uppercase, drop dashes and spaces, read O as 0 and I or L as 1. */
function normalize(raw: string): string | null {
  let out = "";
  for (const ch of raw) {
    if (ch === "-" || /\s/.test(ch)) continue;
    let c = ch.toUpperCase();
    if (c === "O") c = "0";
    else if (c === "I" || c === "L") c = "1";
    if (c.length !== 1 || !PAIRING_ALPHABET.includes(c)) return null;
    out += c;
  }
  return out;
}

/** A fresh 16-character secret (normalized, no dashes). */
export function generatePairingSecret(): string {
  const bytes = new Uint8Array(PAIRING_SECRET_LEN);
  crypto.getRandomValues(bytes);
  // 256 is a multiple of 32, so masking keeps every symbol equally likely.
  return Array.from(bytes, (b) => PAIRING_ALPHABET[b & 31]).join("");
}

/** The code the person types: `XXXXX-XXXXX-XXXX-XXXX-XXXX-XXXX`. */
export function longPairingCode(code: string, secret: string): string {
  const c = normalize(code);
  const s = normalize(secret);
  if (!c || c.length !== PAIRING_CODE_LEN || !s || s.length !== PAIRING_SECRET_LEN) {
    throw new Error("not a pairing code and secret");
  }
  return [c.slice(0, 5), c.slice(5), s.slice(0, 4), s.slice(4, 8), s.slice(8, 12), s.slice(12)].join("-");
}

/**
 * Split what the person typed into the part sent to the server and the
 * secret. A 10-character code has no secret.
 */
export function splitPairingCode(raw: string): { code: string; secret: string | null } | null {
  const all = normalize(raw);
  if (!all) return null;
  const code = `${all.slice(0, 5)}-${all.slice(5, PAIRING_CODE_LEN)}`;
  if (all.length === PAIRING_CODE_LEN) return { code, secret: null };
  if (all.length === PAIRING_CODE_LEN + PAIRING_SECRET_LEN) return { code, secret: all.slice(PAIRING_CODE_LEN) };
  return null;
}

function base64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * The HMAC key for `secret`. Kept non-extractable by default, so a browser
 * that stores it can MAC with it without the secret being readable again.
 */
export async function importPairingKey(secret: string, extractable = false): Promise<CryptoKey> {
  const s = normalize(secret);
  if (!s || s.length !== PAIRING_SECRET_LEN) throw new Error("not a pairing secret");
  return crypto.subtle.importKey("raw", new TextEncoder().encode(s), { name: "HMAC", hash: "SHA-256" }, extractable, [
    "sign",
  ]);
}

async function hmac(secret: string | CryptoKey, message: string): Promise<string> {
  const key = typeof secret === "string" ? await importPairingKey(secret) : secret;
  return base64url(new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message))));
}

/** The computer's MAC over its own keys. */
export function pairingDeviceMac(
  secret: string | CryptoKey,
  credentialId: string,
  did: string,
  enc: string,
): Promise<string> {
  return hmac(secret, `nexusinbox-pair-device-v1\n${credentialId}\n${did}\n${enc}`);
}

/** The browser's MAC over the agent's root. */
export function pairingRootMac(
  secret: string | CryptoKey,
  credentialId: string,
  aid: string,
  root: string,
): Promise<string> {
  return hmac(secret, `nexusinbox-pair-root-v1\n${credentialId}\n${aid}\n${root}`);
}

/** Compare two MACs without an early exit. */
export function macEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
