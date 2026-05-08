/**
 * Local per-credential keystore for Standard mode (SaaS / local keystore).
 *
 * The contract is identical to `templates/agent-runtime-node/_keystore.mjs`
 * so a developer who has already activated a credential via the template
 * can point this server at the same file and start serving immediately:
 *
 *   ~/.nexusinbox/<credential_id>.json
 *     - 0600, atomic rename, JSON
 *     - private keys either plaintext (b64url PKCS8) OR AES-GCM-256
 *       wrapped with a PBKDF2-SHA256 key derived from an optional
 *       passphrase (AGENT_KEYSTORE_PASSPHRASE)
 *     - the one-shot `enrollment_secret` is NEVER persisted; only keys
 *
 * We re-implement the logic here (rather than importing from templates)
 * so the server stays self-contained, which matters because this package
 * will eventually publish to npm separately.
 *
 * Guard rails enforced on every path:
 *   - disk: private keys only; never access/refresh token or DPoP proof
 *   - in-memory: access/refresh tokens, DPoP proof, decrypted message
 *     plaintext — per docs/20_mcp_skill_strategy.md §11
 */

import {
  activateAgentCredential,
  createEd25519KeyPair,
  createX25519KeyPair,
} from "@nexusinbox/core";
import { Algorithm as Argon2Algorithm, hashRaw as argon2HashRaw } from "@node-rs/argon2";
import { promises as fs, constants as fsConstants } from "node:fs";
import os from "node:os";
import path from "node:path";
import { webcrypto } from "node:crypto";

const subtle = webcrypto.subtle;
const textEncoder = new TextEncoder();

// Legacy KDF note: pre-P2 #10 records used PBKDF2-SHA256 at 600_000
// iterations. Those files are still readable (see deriveKekPbkdf2)
// but we no longer emit them — PBKDF2-SHA256 is GPU-parallelisable
// and a stolen keystore file with a weak passphrase cracks in hours
// on consumer hardware. New writes use Argon2id below.

// Argon2id parameters for the current write path. Memory-hard and
// GPU-resistant, matching the Signer Daemon's on-disk protection
// (services/signer-daemon uses Argon2id for its own key files).
//   - memoryCost 64 MiB      (64 * 1024 KiB)
//   - timeCost 3 iterations
//   - parallelism 1          (single-threaded derive is plenty for
//                             one-shot keystore unlocks; raising
//                             parallelism past 1 buys little and
//                             complicates portability)
// Output 32 bytes → AES-GCM-256 KEK via Web Crypto.
const ARGON2_MEMORY_COST_KIB = 64 * 1024;
const ARGON2_TIME_COST = 3;
const ARGON2_PARALLELISM = 1;
const ARGON2_OUTPUT_LEN = 32;

export type LoadOrActivateInput = {
  baseUrl: string;
  aid: string;
  credentialId: string;
  /** Required only on the very first run (when the keystore file does not exist yet). */
  enrollmentSecret?: string;
  /** When set, private keys are stored AES-GCM-256 wrapped; otherwise plaintext. */
  passphrase?: string;
  /** Override the keystore directory (default: $AGENT_KEYSTORE_DIR or ~/.nexusinbox). */
  keystoreDir?: string;
};

export type LoadedCredential = {
  signing: CryptoKeyPair;
  encryption: CryptoKeyPair;
  aid: string;
  did: string;
  activatedAt: string;
  source: "loaded" | "activated";
  keystorePath: string;
};

type EncryptedBlob = { iv_b64url: string; ciphertext_b64url: string };

type Pbkdf2Params = { iterations: number; salt_b64url: string };
type Argon2Params = {
  memory_cost_kib: number;
  time_cost: number;
  parallelism: number;
  salt_b64url: string;
};

type KeystoreRecord = {
  version: 1;
  credential_id: string;
  aid: string;
  did: string;
  activated_at: string;
  signing_public_key: string;
  encryption_public_key: string;
  // Post-P2 #10 writes land as "argon2id". Legacy files with
  // "pbkdf2-sha256" are still accepted on read, and transparently
  // upgraded to Argon2id the next time the server rewrites the
  // record (e.g. on re-activation).
  kdf: "argon2id" | "pbkdf2-sha256" | null;
  kdf_params: Argon2Params | Pbkdf2Params | null;
  signing_private_key: string | EncryptedBlob;
  encryption_private_key: string | EncryptedBlob;
};

function isArgon2Params(v: unknown): v is Argon2Params {
  return (
    typeof v === "object" &&
    v !== null &&
    typeof (v as Argon2Params).memory_cost_kib === "number" &&
    typeof (v as Argon2Params).time_cost === "number" &&
    typeof (v as Argon2Params).parallelism === "number" &&
    typeof (v as Argon2Params).salt_b64url === "string"
  );
}

function isPbkdf2Params(v: unknown): v is Pbkdf2Params {
  return (
    typeof v === "object" &&
    v !== null &&
    typeof (v as Pbkdf2Params).iterations === "number" &&
    typeof (v as Pbkdf2Params).salt_b64url === "string"
  );
}

function b64url(bytes: Uint8Array | ArrayBuffer): string {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  return Buffer.from(u8).toString("base64url");
}
function fromB64url(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64url"));
}

function defaultKeystoreDir(): string {
  return process.env.AGENT_KEYSTORE_DIR ?? path.join(os.homedir(), ".nexusinbox");
}

function keystorePath(dir: string, credentialId: string): string {
  return path.join(dir, `${credentialId}.json`);
}

async function exportPrivatePkcs8(privateKey: CryptoKey): Promise<string> {
  const pkcs8 = new Uint8Array(await subtle.exportKey("pkcs8", privateKey));
  return b64url(pkcs8);
}

async function importPrivatePkcs8(
  b64: string,
  algorithm: AlgorithmIdentifier,
  usages: KeyUsage[],
): Promise<CryptoKey> {
  // P1 hardening: import as **non-extractable**. The MCP server only
  // needs to sign or deriveBits with these keys; it never needs the
  // raw pkcs8 bytes back. Setting `extractable: false` closes the
  // `subtle.exportKey("pkcs8", ...)` escape hatch that a malicious
  // npm dependency could otherwise use to lift the credential's
  // long-lived private key out of process. Memory-scanning attacks
  // are still possible (same as the browser), but the legal export
  // path is gone.
  //
  // The WRITE path (`buildKeystoreRecord` → `exportPrivatePkcs8`)
  // uses a freshly-generated CryptoKeyPair that is created with
  // `extractable: true` in @nexusinbox/core, so the first-run
  // activation flow still works. The shape of the on-disk keystore
  // is unchanged.
  const pkcs8 = fromB64url(b64);
  return subtle.importKey("pkcs8", pkcs8, algorithm, false, usages);
}

/**
 * Derive the AES-GCM 256 KEK from a passphrase using Argon2id with
 * the defaults above. Used for every new keystore write and for
 * reading files produced by the same code path.
 */
/** @internal exported for tests; not part of the package's public API */
export async function _deriveKekArgon2id_testOnly(
  passphrase: string,
  saltBytes: Uint8Array,
  params: Pick<Argon2Params, "memory_cost_kib" | "time_cost" | "parallelism">,
): Promise<CryptoKey> {
  return deriveKekArgon2id(passphrase, saltBytes, params);
}

/** @internal exported for tests; not part of the package's public API */
export async function _deriveKekPbkdf2_testOnly(
  passphrase: string,
  saltBytes: Uint8Array,
  iterations: number,
): Promise<CryptoKey> {
  return deriveKekPbkdf2(passphrase, saltBytes, iterations);
}

async function deriveKekArgon2id(
  passphrase: string,
  saltBytes: Uint8Array,
  params: Pick<Argon2Params, "memory_cost_kib" | "time_cost" | "parallelism">,
): Promise<CryptoKey> {
  const kekBytes = await argon2HashRaw(textEncoder.encode(passphrase), {
    algorithm: Argon2Algorithm.Argon2id,
    salt: Buffer.from(saltBytes),
    memoryCost: params.memory_cost_kib,
    timeCost: params.time_cost,
    parallelism: params.parallelism,
    outputLen: ARGON2_OUTPUT_LEN,
  });
  // Non-extractable KEK — the raw bytes leave Argon2's buffer via
  // importKey below, and after import we hold only the WebCrypto
  // handle, which cannot be re-exported by a compromised dependency.
  return subtle.importKey(
    "raw",
    new Uint8Array(kekBytes),
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/**
 * Legacy PBKDF2-SHA256 derivation for records written before P2 #10.
 * Read-only path: the server still decrypts existing keystore files,
 * but will re-encrypt with Argon2id on the next write so the file
 * migrates out of PBKDF2 without a user-visible step.
 */
async function deriveKekPbkdf2(
  passphrase: string,
  saltBytes: Uint8Array,
  iterations: number,
): Promise<CryptoKey> {
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
      iterations,
    },
    pwKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function encryptBytes(plaintextB64Url: string, kek: CryptoKey): Promise<EncryptedBlob> {
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const pt = fromB64url(plaintextB64Url);
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv }, kek, pt));
  return { iv_b64url: b64url(iv), ciphertext_b64url: b64url(ct) };
}

async function decryptBytes(blob: EncryptedBlob, kek: CryptoKey): Promise<string> {
  const iv = fromB64url(blob.iv_b64url);
  const ct = fromB64url(blob.ciphertext_b64url);
  const pt = new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv }, kek, ct));
  return b64url(pt);
}

async function atomicWrite(filePath: string, data: string): Promise<void> {
  const dir = path.dirname(filePath);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  const tmp = `${filePath}.${process.pid}.${Date.now()}.tmp`;
  await fs.writeFile(tmp, data, { mode: 0o600 });
  await fs.rename(tmp, filePath);
  try {
    await fs.chmod(filePath, 0o600);
  } catch {
    // best effort — on some filesystems chmod is a no-op but not an error signal
  }
}

async function readIfExists(filePath: string): Promise<KeystoreRecord | null> {
  try {
    await fs.access(filePath, fsConstants.F_OK);
  } catch {
    return null;
  }
  const raw = await fs.readFile(filePath, "utf8");
  return JSON.parse(raw) as KeystoreRecord;
}

async function recordToKeyPairs(
  record: KeystoreRecord,
  passphrase: string | undefined,
): Promise<Pick<LoadedCredential, "signing" | "encryption">> {
  const isEncrypted = Boolean(record.kdf);
  if (isEncrypted && !passphrase) {
    throw new Error(
      `keystore file ${record.credential_id} is passphrase-encrypted; ` +
        `set AGENT_KEYSTORE_PASSPHRASE to load it.`,
    );
  }

  let signingPrivB64: string;
  let encryptionPrivB64: string;

  if (isEncrypted) {
    if (!record.kdf_params) {
      throw new Error(`keystore has kdf=${record.kdf} but no kdf_params`);
    }
    let kek: CryptoKey;
    if (record.kdf === "argon2id" && isArgon2Params(record.kdf_params)) {
      const salt = fromB64url(record.kdf_params.salt_b64url);
      kek = await deriveKekArgon2id(passphrase!, salt, record.kdf_params);
    } else if (record.kdf === "pbkdf2-sha256" && isPbkdf2Params(record.kdf_params)) {
      // Read-only legacy path — keystores written before P2 #10.
      // They continue to load, and the next buildKeystoreRecord
      // call (e.g. re-activation) rewrites them with Argon2id.
      const salt = fromB64url(record.kdf_params.salt_b64url);
      kek = await deriveKekPbkdf2(passphrase!, salt, record.kdf_params.iterations);
    } else {
      throw new Error(`unsupported keystore kdf: ${record.kdf}`);
    }
    try {
      signingPrivB64 = await decryptBytes(record.signing_private_key as EncryptedBlob, kek);
      encryptionPrivB64 = await decryptBytes(
        record.encryption_private_key as EncryptedBlob,
        kek,
      );
    } catch {
      throw new Error("failed to decrypt keystore — wrong AGENT_KEYSTORE_PASSPHRASE?");
    }
  } else {
    signingPrivB64 = record.signing_private_key as string;
    encryptionPrivB64 = record.encryption_private_key as string;
  }

  const signingPriv = await importPrivatePkcs8(signingPrivB64, { name: "Ed25519" }, ["sign"]);
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
    signing: { privateKey: signingPriv, publicKey: signingPub } as CryptoKeyPair,
    encryption: { privateKey: encryptionPriv, publicKey: encryptionPub } as CryptoKeyPair,
  };
}

async function buildKeystoreRecord(args: {
  credentialId: string;
  aid: string;
  did: string;
  signing: CryptoKeyPair;
  encryption: CryptoKeyPair;
  passphrase: string | undefined;
}): Promise<KeystoreRecord> {
  const signingPrivPlain = await exportPrivatePkcs8(args.signing.privateKey);
  const encryptionPrivPlain = await exportPrivatePkcs8(args.encryption.privateKey);
  const signingPubRaw = new Uint8Array(await subtle.exportKey("raw", args.signing.publicKey));
  const encryptionPubRaw = new Uint8Array(
    await subtle.exportKey("raw", args.encryption.publicKey),
  );

  const base: KeystoreRecord = {
    version: 1,
    credential_id: args.credentialId,
    aid: args.aid,
    did: args.did,
    activated_at: new Date().toISOString(),
    signing_public_key: b64url(signingPubRaw),
    encryption_public_key: b64url(encryptionPubRaw),
    kdf: null,
    kdf_params: null,
    signing_private_key: signingPrivPlain,
    encryption_private_key: encryptionPrivPlain,
  };

  if (args.passphrase) {
    // P2 #10: all new writes use Argon2id. The shape includes
    // explicit memoryCost / timeCost / parallelism so a future bump
    // to stronger params is self-describing — each record carries
    // the parameters it was written with.
    const salt = webcrypto.getRandomValues(new Uint8Array(16));
    const kek = await deriveKekArgon2id(args.passphrase, salt, {
      memory_cost_kib: ARGON2_MEMORY_COST_KIB,
      time_cost: ARGON2_TIME_COST,
      parallelism: ARGON2_PARALLELISM,
    });
    base.kdf = "argon2id";
    base.kdf_params = {
      memory_cost_kib: ARGON2_MEMORY_COST_KIB,
      time_cost: ARGON2_TIME_COST,
      parallelism: ARGON2_PARALLELISM,
      salt_b64url: b64url(salt),
    };
    base.signing_private_key = await encryptBytes(signingPrivPlain, kek);
    base.encryption_private_key = await encryptBytes(encryptionPrivPlain, kek);
  }
  return base;
}

export async function loadOrActivateCredential(
  input: LoadOrActivateInput,
): Promise<LoadedCredential> {
  if (!input.credentialId) throw new Error("credentialId is required");
  const dir = input.keystoreDir ?? defaultKeystoreDir();
  const filePath = keystorePath(dir, input.credentialId);

  const existing = await readIfExists(filePath);
  if (existing) {
    if (existing.aid !== input.aid) {
      throw new Error(
        `keystore for credential ${input.credentialId} holds aid=${existing.aid} ` +
          `but current run was asked for aid=${input.aid}. Refusing to reuse.`,
      );
    }
    const loaded = await recordToKeyPairs(existing, input.passphrase);
    return {
      ...loaded,
      aid: existing.aid,
      did: existing.did,
      activatedAt: existing.activated_at,
      source: "loaded",
      keystorePath: filePath,
    };
  }

  if (!input.enrollmentSecret) {
    throw new Error(
      `No keystore at ${filePath} and no enrollmentSecret provided. Pass the one-shot ` +
        `ens_… from the credential you just created (env: AGENT_ENROLLMENT_SECRET).`,
    );
  }

  const signing = await createEd25519KeyPair();
  const encryption = await createX25519KeyPair();

  const activated = await activateAgentCredential({
    baseUrl: input.baseUrl,
    credentialId: input.credentialId,
    enrollmentSecret: input.enrollmentSecret,
    signingKeyPair: signing,
    encryptionKeyPair: encryption,
  });

  if (activated.aid !== input.aid) {
    throw new Error(
      `activate returned aid=${activated.aid}, expected ${input.aid}. Aborting before ` +
        `writing keystore to avoid a confused-deputy record.`,
    );
  }

  const record = await buildKeystoreRecord({
    credentialId: input.credentialId,
    aid: activated.aid,
    did: activated.did,
    signing,
    encryption,
    passphrase: input.passphrase,
  });
  await atomicWrite(filePath, JSON.stringify(record, null, 2));

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
