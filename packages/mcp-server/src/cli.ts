#!/usr/bin/env node
/**
 * nexusinbox-mcp CLI.
 *
 * Modes:
 *   --print-manifest       → dump the tool catalog as JSON (no network)
 *   --init                 → consume AGENT_ENROLLMENT_SECRET once and
 *                            materialise the keystore; used on the very
 *                            first run before Claude Desktop takes over
 *   --stdio (default)      → boot the MCP stdio server for Standard mode
 *
 * Required env vars:
 *   AGENT_INBOX_BASE_URL   defaults to https://api.nexusinbox.ai
 *   AGENT_AID              aid:ai:...
 *   AGENT_CREDENTIAL_ID    uuid from the credential created in the UI
 *
 * First run only:
 *   AGENT_ENROLLMENT_SECRET   ens_...
 *
 * Optional:
 *   AGENT_KEYSTORE_PASSPHRASE strongly recommended (AES-GCM + PBKDF2)
 *   AGENT_KEYSTORE_DIR        defaults to ~/.nexusinbox
 *   AGENT_INBOX_MCP_TOOLS     comma-separated allowlist (default: all
 *                             registered Phase 1A/1B tools)
 */

import { createGatewayRuntime, MODE_A_TOOL_ALLOWLIST } from "./runtime-gateway.js";
import { createSaasRuntime } from "./runtime-saas.js";
import { startStdioServer } from "./server.js";
import { buildManifest } from "./index.js";

function printHelp(): void {
  process.stdout.write(`nexusinbox-mcp

Usage:
  nexusinbox-mcp [--stdio]      Boot the MCP stdio server (default)
  nexusinbox-mcp --print-manifest
  nexusinbox-mcp --init
  nexusinbox-mcp --help

Deployment modes (AGENT_INBOX_MCP_MODE):
  mode_b_saas_keystore (default)  Local keystore + in-memory tokens.
                                  Full read + send. Requires AGENT_AID +
                                  AGENT_CREDENTIAL_ID, first-time ens_.
  mode_a_gateway_daemon           Self-hosted Signer Daemon + Gateway.
                                  Full 6-tool surface (Phase 2.5):
                                  read_message decrypts via the
                                  daemon's unwrap_content_key RPC, so
                                  the recipient's X25519 private key
                                  never leaves the daemon process.
                                  Requires AGENT_INBOX_GATEWAY_SOCKET
                                  and the daemon launched with
                                  --encryption-key-file.

Standard mode env:
  AGENT_INBOX_BASE_URL       default: https://api.nexusinbox.ai
  AGENT_AID                  aid:ai:... (required)
  AGENT_CREDENTIAL_ID        credential uuid (required)
  AGENT_ENROLLMENT_SECRET    ens_... (first run only)
  AGENT_KEYSTORE_PASSPHRASE  recommended; encrypts keystore at rest
  AGENT_KEYSTORE_DIR         default: ~/.nexusinbox

Isolated mode env:
  AGENT_INBOX_GATEWAY_SOCKET default: /tmp/nexusinbox-gateway.sock

Shared env:
  AGENT_INBOX_MCP_TOOLS      CSV tool allowlist (default: all supported
                             by the selected mode)
`);
}

function requireEnv(name: string): string {
  const v = process.env[name];
  if (!v || v.trim().length === 0) {
    process.stderr.write(`[nexusinbox-mcp] missing required env: ${name}\n`);
    process.exit(1);
  }
  return v.trim();
}

function optionalEnv(name: string): string | undefined {
  const v = process.env[name];
  return v && v.trim().length > 0 ? v.trim() : undefined;
}

function parseToolsAllowlist(): string[] | undefined {
  const raw = optionalEnv("AGENT_INBOX_MCP_TOOLS");
  if (!raw) return undefined;
  return raw.split(",").map((s) => s.trim()).filter(Boolean);
}

async function runInit(): Promise<void> {
  const baseUrl =
    optionalEnv("AGENT_INBOX_BASE_URL") ?? "https://api.nexusinbox.ai";
  const aid = requireEnv("AGENT_AID");
  const credentialId = requireEnv("AGENT_CREDENTIAL_ID");
  const enrollmentSecret = requireEnv("AGENT_ENROLLMENT_SECRET");
  const passphrase = optionalEnv("AGENT_KEYSTORE_PASSPHRASE");
  const keystoreDir = optionalEnv("AGENT_KEYSTORE_DIR");

  const { credential } = await createSaasRuntime({
    baseUrl,
    aid,
    credentialId,
    enrollmentSecret,
    passphrase,
    keystoreDir,
  });
  process.stdout.write(
    JSON.stringify(
      {
        ok: true,
        source: credential.source,
        keystore: credential.keystorePath,
        aid: credential.aid,
        did: credential.did,
        activated_at: credential.activatedAt,
      },
      null,
      2,
    ) + "\n",
  );
}

async function runStdio(): Promise<void> {
  const mode = pickMode();
  if (mode === "mode_a_gateway_daemon") {
    await runStdioModeA();
    return;
  }
  await runStdioModeB();
}

type ActiveMode = "mode_a_gateway_daemon" | "mode_b_saas_keystore";

function pickMode(): ActiveMode {
  const raw = optionalEnv("AGENT_INBOX_MCP_MODE")?.toLowerCase();
  if (!raw || raw === "mode_b" || raw === "mode_b_saas_keystore" || raw === "saas") {
    return "mode_b_saas_keystore";
  }
  if (raw === "mode_a" || raw === "mode_a_gateway_daemon" || raw === "gateway") {
    return "mode_a_gateway_daemon";
  }
  process.stderr.write(
    `[nexusinbox-mcp] unknown AGENT_INBOX_MCP_MODE=${raw}; falling back to mode_b_saas_keystore\n`,
  );
  return "mode_b_saas_keystore";
}

async function runStdioModeB(): Promise<void> {
  const baseUrl =
    optionalEnv("AGENT_INBOX_BASE_URL") ?? "https://api.nexusinbox.ai";
  const aid = requireEnv("AGENT_AID");
  const credentialId = requireEnv("AGENT_CREDENTIAL_ID");
  // `enrollmentSecret` is optional at runtime: on subsequent boots the
  // keystore already has the keypair, so we don't want to force users
  // to keep the secret in Claude Desktop's config forever.
  const enrollmentSecret = optionalEnv("AGENT_ENROLLMENT_SECRET");
  const passphrase = optionalEnv("AGENT_KEYSTORE_PASSPHRASE");
  const keystoreDir = optionalEnv("AGENT_KEYSTORE_DIR");

  const { runtime } = await createSaasRuntime({
    baseUrl,
    aid,
    credentialId,
    enrollmentSecret,
    passphrase,
    keystoreDir,
  });
  await startStdioServer({
    runtime,
    activeMode: "mode_b_saas_keystore",
    enabledTools: parseToolsAllowlist(),
  });
}

async function runStdioModeA(): Promise<void> {
  const socketPath = optionalEnv("AGENT_INBOX_GATEWAY_SOCKET");
  const { runtime, supportedTools } = await createGatewayRuntime({
    socketPath,
  });
  // Intersection: caller-specified allowlist ∩ Mode-A-supported tools.
  // The intersection avoids the server advertising tools the runtime
  // would immediately reject, while still letting an operator further
  // narrow the surface (e.g. read-only sidecars disable send).
  const requested = parseToolsAllowlist();
  const enabledTools = requested
    ? supportedTools.filter((t) => requested.includes(t))
    : supportedTools;
  await startStdioServer({
    runtime,
    activeMode: "mode_a_gateway_daemon",
    enabledTools,
  });
  // Suppress "unused" warning in case Isolated mode grows more options later.
  void MODE_A_TOOL_ALLOWLIST;
}

async function main(): Promise<void> {
  const arg = process.argv[2];

  if (arg === "--help" || arg === "-h") {
    printHelp();
    return;
  }
  if (arg === "--print-manifest") {
    process.stdout.write(`${JSON.stringify(buildManifest(), null, 2)}\n`);
    return;
  }
  if (arg === "--init") {
    await runInit();
    return;
  }
  if (arg === undefined || arg === "--stdio") {
    await runStdio();
    return;
  }
  process.stderr.write(`[nexusinbox-mcp] unknown argument: ${arg}\n`);
  printHelp();
  process.exit(1);
}

main().catch((error) => {
  process.stderr.write(
    `[nexusinbox-mcp] fatal: ${error instanceof Error ? error.message : String(error)}\n`,
  );
  process.exit(1);
});
