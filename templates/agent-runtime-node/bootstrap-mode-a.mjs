#!/usr/bin/env node
/**
 * Bootstrap an Isolated-mode (Signer Daemon) credential against the live API.
 *
 * What this does
 * --------------
 * 1. Generate fresh Ed25519 (signing) + X25519 (encryption) keypairs
 *    via the same `@nexusinbox/core` helpers Standard mode uses.
 * 2. POST `/agent-credentials/:id/activate` with the public halves +
 *    the one-shot enrollment_secret. Server stores the public keys
 *    against the credential and consumes the secret.
 * 3. Write the raw 32-byte private keys to plaintext files the daemon
 *    can read with `--unsafe-plaintext-key`. Files are created with
 *    mode 0600 inside the user-specified daemon dir.
 *
 * Why plaintext instead of the daemon's encrypted format
 * ------------------------------------------------------
 * The daemon's at-rest format is Argon2id + XChaCha20-Poly1305, which
 * we don't want to re-implement in Node just for bootstrap. The
 * "test in production" path is therefore:
 *
 *   bootstrap → plaintext keys (0600) → daemon --unsafe-plaintext-key
 *
 * Once you decide to keep the credential, regenerate with the daemon's
 * own `--generate` mode + a passphrase and rerun this script using the
 * pubkeys it prints.
 *
 * Required env (read from .env via --env-file or exported)
 * --------------------------------------------------------
 *   AGENT_INBOX_BASE_URL      e.g. https://api.nexusinbox.ai
 *   AGENT_AID                 aid:ai:YOUR_AGENT
 *   AGENT_CREDENTIAL_ID       <credential uuid> (from the web UI)
 *   AGENT_ENROLLMENT_SECRET   ens_... (one-shot, consumed here)
 *
 * Optional:
 *   AGENT_DAEMON_DIR          default: ~/.nexusinbox/daemon
 */

import { mkdir, writeFile, chmod } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";
import { webcrypto as crypto } from "node:crypto";
import {
  activateAgentCredential,
  createEd25519KeyPair,
  createX25519KeyPair,
} from "../../packages/core/dist/index.js";

function required(name) {
  const v = process.env[name];
  if (!v || v.trim().length === 0) {
    console.error(`[bootstrap] missing required env: ${name}`);
    process.exit(1);
  }
  return v.trim();
}

function optional(name, fallback) {
  const v = process.env[name];
  return v && v.trim().length > 0 ? v.trim() : fallback;
}

function toB64Url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

async function exportRawPrivate(cryptoKey) {
  // Web Crypto exports private keys as PKCS#8/JWK only. We need the
  // raw 32-byte seed/scalar that the Rust daemon expects. Use JWK and
  // extract the `d` field, which is base64url(32 raw bytes) for both
  // Ed25519 and X25519.
  const jwk = await crypto.subtle.exportKey("jwk", cryptoKey);
  if (!jwk.d) {
    throw new Error("exported JWK missing 'd' (private scalar)");
  }
  const raw = Buffer.from(jwk.d, "base64url");
  if (raw.byteLength !== 32) {
    throw new Error(`expected 32-byte private key, got ${raw.byteLength}`);
  }
  return raw;
}

async function main() {
  const baseUrl = required("AGENT_INBOX_BASE_URL");
  const aid = required("AGENT_AID");
  const credentialId = required("AGENT_CREDENTIAL_ID");
  const enrollmentSecret = required("AGENT_ENROLLMENT_SECRET");
  const daemonDir = optional(
    "AGENT_DAEMON_DIR",
    path.join(homedir(), ".nexusinbox", "daemon"),
  );

  console.log("=== Isolated mode bootstrap ===");
  console.log("API base:    ", baseUrl);
  console.log("AID:         ", aid);
  console.log("Credential:  ", credentialId);
  console.log("Daemon dir:  ", daemonDir);
  console.log();

  // 1. Generate fresh keypairs.
  console.log("[1/3] Generating Ed25519 + X25519 keypairs...");
  const signing = await createEd25519KeyPair();
  const encryption = await createX25519KeyPair();

  // 2. Activate against the live API. Server consumes ens_... here.
  console.log("[2/3] Activating credential against the API...");
  const activated = await activateAgentCredential({
    baseUrl,
    credentialId,
    enrollmentSecret,
    signingKeyPair: signing,
    encryptionKeyPair: encryption,
    // Isolated mode bootstrap: tell the server the keys are going to sit in
    // a Signer Daemon so the Web UI can surface an honest
    // Daemon-isolated badge (docs/21 §7) instead of optimistically
    // assuming a browser keystore.
    keyHolder: "signer_daemon",
  });
  if (activated.aid !== aid) {
    throw new Error(
      `activate returned aid=${activated.aid}, expected ${aid}. ` +
        "Re-check AGENT_AID + AGENT_CREDENTIAL_ID — they must match the same row.",
    );
  }
  console.log("    activated aid:", activated.aid);
  console.log("    did:          ", activated.did);

  // 3. Write the plaintext key files for the daemon.
  console.log("[3/3] Writing daemon key files (mode 0600)...");
  await mkdir(daemonDir, { recursive: true, mode: 0o700 });
  const signingPath = path.join(daemonDir, "signing.key");
  const encryptionPath = path.join(daemonDir, "encryption.key");

  const signingRaw = await exportRawPrivate(signing.privateKey);
  const encryptionRaw = await exportRawPrivate(encryption.privateKey);

  await writeFile(signingPath, signingRaw, { mode: 0o600 });
  await chmod(signingPath, 0o600);
  await writeFile(encryptionPath, encryptionRaw, { mode: 0o600 });
  await chmod(encryptionPath, 0o600);

  console.log("    signing key:    ", signingPath);
  console.log("    encryption key: ", encryptionPath);
  console.log();
  console.log("=== Done. Next steps ===");
  console.log();
  // Resolve absolute paths to the built release binaries so copy-paste
  // works regardless of which dir the user is sitting in.
  const repoRoot = path.resolve(import.meta.dirname, "..", "..");
  const signerBin = path.join(
    repoRoot,
    "services",
    "signer-daemon",
    "target",
    "release",
    "nexusinbox-signer",
  );
  const gatewayBin = path.join(
    repoRoot,
    "services",
    "agent-gateway",
    "target",
    "release",
    "nexusinbox-gateway",
  );
  console.log("# 1. Launch the Signer Daemon (in its own terminal):");
  console.log(`${signerBin} \\
  --unsafe-plaintext-key \\
  --key-file ${signingPath} \\
  --encryption-key-file ${encryptionPath} \\
  --aid ${aid} \\
  --credential-id ${credentialId} \\
  --api-url ${baseUrl}`);
  console.log();
  console.log("# 2. Launch the Gateway (in another terminal):");
  console.log(`${gatewayBin} \\
  --signer-socket /tmp/nexusinbox-signer.sock \\
  --api-url ${baseUrl}`);
  console.log();
  console.log("# 3. Sanity check the Gateway socket from Node:");
  console.log("AGENT_INBOX_GATEWAY_SOCKET=/tmp/nexusinbox-gateway.sock \\");
  console.log("  pnpm --dir templates/agent-runtime-node gateway");
  console.log();
  console.log(
    "# 4. Point Claude Desktop at packages/mcp-server/dist/cli.js with",
  );
  console.log(
    "#    AGENT_INBOX_MCP_MODE=mode_a_gateway_daemon — see",
  );
  console.log("#    packages/mcp-server/README.md → Isolated mode section.");
  console.log();
  console.log("[security] Plaintext key files are 0600. Treat the daemon dir");
  console.log("           like ~/.ssh and do NOT back it up to the cloud.");
}

main().catch((error) => {
  console.error("[bootstrap] fatal:", error?.message ?? error);
  process.exit(1);
});
