/**
 * CLI smoke tests — these exercise `dist/cli.js` out-of-process so we
 * catch regressions in flag parsing, required-env validation, and
 * startup error paths without spinning up a real MCP client.
 *
 * The test suite depends on the package having been built first
 * (`pnpm --filter @nexusinbox/mcp-server build`). `vitest run` at the
 * workspace level runs `build` implicitly via the test command alias,
 * and here we defensively re-assert the dist file exists so a missing
 * build fails loudly with an actionable message instead of a cryptic
 * "MODULE_NOT_FOUND".
 */

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const CLI_PATH = path.resolve(__dirname, "../dist/cli.js");

type RunResult = {
  stdout: string;
  stderr: string;
  exitCode: number | null;
};

function runCli(args: string[], env: NodeJS.ProcessEnv = {}): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    if (!existsSync(CLI_PATH)) {
      reject(
        new Error(
          `CLI bundle missing at ${CLI_PATH}. Run \`pnpm --filter @nexusinbox/mcp-server build\` first.`,
        ),
      );
      return;
    }
    const child = spawn(process.execPath, [CLI_PATH, ...args], {
      env: { ...process.env, ...env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => {
      stdout += d.toString();
    });
    child.stderr.on("data", (d) => {
      stderr += d.toString();
    });
    child.on("exit", (code) => resolve({ stdout, stderr, exitCode: code }));
    child.on("error", reject);
  });
}

describe("nexusinbox-mcp CLI", () => {
  it("--print-manifest writes JSON to stdout and exits 0", async () => {
    const { stdout, stderr, exitCode } = await runCli(["--print-manifest"]);
    expect(exitCode).toBe(0);
    expect(stderr).toBe("");
    const parsed = JSON.parse(stdout);
    expect(parsed.name).toBe("@nexusinbox/mcp-server");
    expect(parsed.deployment_modes).toContain("mode_b_saas_keystore");
    expect(parsed.tools.map((t: { name: string }) => t.name)).toContain("list_inbox");
  });

  it("--help prints usage and exits 0", async () => {
    const { stdout, exitCode } = await runCli(["--help"]);
    expect(exitCode).toBe(0);
    expect(stdout).toContain("nexusinbox-mcp");
    expect(stdout).toContain("AGENT_INBOX_BASE_URL");
  });

  it("unknown flag prints usage to stderr and exits non-zero", async () => {
    const { stderr, exitCode } = await runCli(["--banana"]);
    expect(exitCode).not.toBe(0);
    expect(stderr).toContain("unknown argument");
  });

  it("--stdio with no env fails fast with a readable message", async () => {
    const { stderr, exitCode } = await runCli(["--stdio"], {
      AGENT_AID: "",
      AGENT_CREDENTIAL_ID: "",
    });
    expect(exitCode).not.toBe(0);
    expect(stderr).toMatch(/missing required env: AGENT_AID/);
  });
});
