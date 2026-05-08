/**
 * NexusInbox credential keystore — local, persistent.
 *
 * Purpose: avoid burning a fresh enrollment secret (ens_…) on every run.
 * One-shot secrets are consumed on `activateAgentCredential`; without
 * persistence, runtimes regenerate keypairs on every boot and need a new
 * ens_ each time. That's a showstopper for non-interactive agents.
 *
 * This module keeps it simple:
 *   1. Generate keypair once, activate the credential with the one-shot
 *      ens_… , save private keys to disk.
 *   2. Re-runs load the saved keys; `ens_…` is no longer needed and is
 *      ignored if passed.
 *
 * Storage shape (~/.nexusinbox/<credentialId>.json by default):
 *   {
 *     "version": 1,
 *     "credential_id", "aid", "did",
 *     "activated_at",
 *     "signing_public_key", "encryption_public_key",   // base64url
 *     "signing_private_key":   <plain b64url string | encrypted blob>,
 *     "encryption_private_key": <plain b64url string | encrypted blob>,
 *     "kdf": "pbkdf2-sha256" | null,
 *     "kdf_params": { "iterations": 600000, "salt_b64url": "…" } | null
 *   }
 *
 * Encrypted blob shape:
 *   { "iv_b64url": "…", "ciphertext_b64url": "…" }   // AES-GCM-256
 *
 * Security posture:
 *   - 0600 file perms + atomic rename on write.
 *   - enrollment_secret is NEVER persisted — only private keys.
 *   - Passphrase-based encryption is optional (AGENT_KEYSTORE_PASSPHRASE
 *     env var). Plaintext fallback prints a visible warning.
 *   - Crypto is pure Web Crypto / node:crypto — no native deps.
 *   - Not compatible with services/signer-daemon's at-rest format
 *     (XChaCha20-Poly1305 + Argon2id, raw layout) — we use PBKDF2 +
 *     AES-GCM here to stay dep-free for starter templates.
 */

import {
  createEd25519KeyPair,
  createX25519KeyPair,
  activateAgentCredential,
} from "../../packages/core/dist/index.js";
import { promises as fs, constants as fsConstants } from "node:fs";
import os from "node:os";
import path from "node:path";
import { webcrypto } from "node:crypto";

const subtle = webcrypto.subtle;
const textEncoder = new TextEncoder();
const PBKDF2_ITERATIONS = 600_000;

function b64url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}
function fromB64url(s) {
  return new Uint8Array(Buffer.from(s, "base64url"));
}

function defaultKeystoreDir() {
  return (
    process.env.AGENT_KEYSTORE_DIR ?? path.join(os.homedir(), ".nexusinbox")
  );
}
function keystorePath(dir, credentialId) {
  return path.join(dir, `${credentialId}.json`);
}

/**
 * Export a WebCrypto private key to base64url(pkcs8) and vice versa.
 * PKCS#8 keeps the algorithm identifier so re-import is unambiguous.
 */
async function exportPrivatePkcs8(privateKey) {
  const pkcs8 = new Uint8Array(await subtle.exportKey("pkcs8", privateKey));
  return b64url(pkcs8);
}
async function importPrivatePkcs8(b64, algorithm, usages) {
  const pkcs8 = fromB64url(b64);
  return subtle.importKey("pkcs8", pkcs8, algorithm, true, usages);
}

async function deriveKek(passphrase, saltBytes) {
  const pwKey = await subtle.importKey(
    "raw",
    textEncoder.encode(passphrase),
    { name: "PBKDF2" },
    false,
    ["deriveKey"],
  );
  return subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: saltBytes,
      iterations: PBKDF2_ITERATIONS,
    },
    pwKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function encryptBytes(plaintextB64Url, kek) {
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const pt = fromB64url(plaintextB64Url);
  const ct = new Uint8Array(
    await subtle.encrypt({ name: "AES-GCM", iv }, kek, pt),
  );
  return { iv_b64url: b64url(iv), ciphertext_b64url: b64url(ct) };
}
async function decryptBytes(blob, kek) {
  const iv = fromB64url(blob.iv_b64url);
  const ct = fromB64url(blob.ciphertext_b64url);
  const pt = new Uint8Array(
    await subtle.decrypt({ name: "AES-GCM", iv }, kek, ct),
  );
  return b64url(pt);
}

async function atomicWrite(filePath, data) {
  const dir = path.dirname(filePath);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  const tmp = `${filePath}.${process.pid}.${Date.now()}.tmp`;
  // 0o600 from the start so a crash between open() and chmod() can't leave
  // a world-readable key file on disk.
  await fs.writeFile(tmp, data, { mode: 0o600 });
  await fs.rename(tmp, filePath);
  // Enforce 0600 defensively in case of umask weirdness on first write.
  try {
    await fs.chmod(filePath, 0o600);
  } catch {}
}

async function readIfExists(filePath) {
  try {
    await fs.access(filePath, fsConstants.F_OK);
  } catch {
    return null;
  }
  const raw = await fs.readFile(filePath, "utf8");
  return JSON.parse(raw);
}

async function buildKeystoreRecord({
  credentialId,
  aid,
  did,
  signingKeyPair,
  encryptionKeyPair,
  passphrase,
}) {
  const signingPrivPlain = await exportPrivatePkcs8(signingKeyPair.privateKey);
  const encryptionPrivPlain = await exportPrivatePkcs8(
    encryptionKeyPair.privateKey,
  );
  const signingPubRaw = new Uint8Array(
    await subtle.exportKey("raw", signingKeyPair.publicKey),
  );
  const encryptionPubRaw = new Uint8Array(
    await subtle.exportKey("raw", encryptionKeyPair.publicKey),
  );

  const base = {
    version: 1,
    credential_id: credentialId,
    aid,
    did,
    activated_at: new Date().toISOString(),
    signing_public_key: b64url(signingPubRaw),
    encryption_public_key: b64url(encryptionPubRaw),
  };

  if (passphrase) {
    const salt = webcrypto.getRandomValues(new Uint8Array(16));
    const kek = await deriveKek(passphrase, salt);
    base.kdf = "pbkdf2-sha256";
    base.kdf_params = {
      iterations: PBKDF2_ITERATIONS,
      salt_b64url: b64url(salt),
    };
    base.signing_private_key = await encryptBytes(signingPrivPlain, kek);
    base.encryption_private_key = await encryptBytes(encryptionPrivPlain, kek);
  } else {
    base.kdf = null;
    base.kdf_params = null;
    base.signing_private_key = signingPrivPlain;
    base.encryption_private_key = encryptionPrivPlain;
  }
  return base;
}

async function recordToKeyPair(record, passphrase) {
  const isEncrypted = Boolean(record.kdf);
  if (isEncrypted && !passphrase) {
    throw new Error(
      `keystore file ${record.credential_id} is passphrase-encrypted; ` +
        `set AGENT_KEYSTORE_PASSPHRASE to load it.`,
    );
  }
  if (!isEncrypted && passphrase) {
    console.warn(
      "[keystore] file is plaintext but AGENT_KEYSTORE_PASSPHRASE is set — " +
        "consider rotating to an encrypted keystore (delete the file and rerun).",
    );
  }

  let signingPrivB64;
  let encryptionPrivB64;
  if (isEncrypted) {
    if (record.kdf !== "pbkdf2-sha256") {
      throw new Error(`unsupported keystore kdf: ${record.kdf}`);
    }
    const salt = fromB64url(record.kdf_params.salt_b64url);
    const kek = await deriveKek(passphrase, salt);
    try {
      signingPrivB64 = await decryptBytes(record.signing_private_key, kek);
      encryptionPrivB64 = await decryptBytes(
        record.encryption_private_key,
        kek,
      );
    } catch {
      throw new Error(
        "failed to decrypt keystore — wrong AGENT_KEYSTORE_PASSPHRASE?",
      );
    }
  } else {
    signingPrivB64 = record.signing_private_key;
    encryptionPrivB64 = record.encryption_private_key;
  }

  const signingPriv = await importPrivatePkcs8(
    signingPrivB64,
    { name: "Ed25519" },
    ["sign"],
  );
  const signingPub = await subtle.importKey(
    "raw",
    fromB64url(record.signing_public_key),
    { name: "Ed25519" },
    true,
    ["verify"],
  );
  const encryptionPriv = await importPrivatePkcs8(
    encryptionPrivB64,
    { name: "X25519" },
    ["deriveBits"],
  );
  const encryptionPub = await subtle.importKey(
    "raw",
    fromB64url(record.encryption_public_key),
    { name: "X25519" },
    true,
    [],
  );
  return {
    signing: { privateKey: signingPriv, publicKey: signingPub },
    encryption: { privateKey: encryptionPriv, publicKey: encryptionPub },
    aid: record.aid,
    did: record.did,
    activatedAt: record.activated_at,
  };
}

/**
 * Load the saved keypair for `credentialId`, or activate and save on first run.
 *
 * Returns: { signing, encryption, aid, did, activatedAt, source }
 *   source: "loaded" if read from disk, "activated" if freshly activated.
 *
 * Inputs:
 *   baseUrl, aid, credentialId — required
 *   enrollmentSecret — required on FIRST run (activation); ignored afterward
 *   passphrase        — optional (AGENT_KEYSTORE_PASSPHRASE)
 *   keystoreDir       — optional (AGENT_KEYSTORE_DIR | ~/.nexusinbox)
 */
export async function loadOrActivateCredential({
  baseUrl,
  aid,
  credentialId,
  enrollmentSecret,
  passphrase,
  keystoreDir,
}) {
  if (!credentialId) throw new Error("credentialId is required");
  const dir = keystoreDir ?? defaultKeystoreDir();
  const filePath = keystorePath(dir, credentialId);

  const existing = await readIfExists(filePath);
  if (existing) {
    if (existing.aid !== aid) {
      throw new Error(
        `keystore for credential ${credentialId} holds aid=${existing.aid} ` +
          `but current run was asked for aid=${aid}. Refusing to reuse.`,
      );
    }
    const loaded = await recordToKeyPair(existing, passphrase);
    return { ...loaded, source: "loaded", keystorePath: filePath };
  }

  // First-run activation path.
  if (!enrollmentSecret) {
    throw new Error(
      `No keystore at ${filePath} and no AGENT_ENROLLMENT_SECRET provided. ` +
        `Pass the one-shot ens_… from the credential you just created.`,
    );
  }
  const signing = await createEd25519KeyPair();
  const encryption = await createX25519KeyPair();

  const activated = await activateAgentCredential({
    baseUrl,
    credentialId,
    enrollmentSecret,
    signingKeyPair: signing,
    encryptionKeyPair: encryption,
  });
  if (activated.aid !== aid) {
    throw new Error(
      `activate returned aid=${activated.aid}, expected ${aid}. Aborting ` +
        `before writing keystore to avoid a confused-deputy record.`,
    );
  }

  const record = await buildKeystoreRecord({
    credentialId,
    aid: activated.aid,
    did: activated.did,
    signingKeyPair: signing,
    encryptionKeyPair: encryption,
    passphrase,
  });
  await atomicWrite(filePath, JSON.stringify(record, null, 2));

  if (!passphrase) {
    console.warn(
      `[keystore] wrote PLAINTEXT private keys to ${filePath}. ` +
        `Set AGENT_KEYSTORE_PASSPHRASE before the first run to encrypt at rest.`,
    );
  }
  return {
    signing,
    encryption,
    aid: activated.aid,
    did: activated.did,
    activatedAt: record.activated_at,
    source: "activated",
    keystorePath: filePath,
  };
}
