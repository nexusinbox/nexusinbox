import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { gatewaySocketProblem, NexusInboxGatewayClient } from "../src/index";

const dirs: string[] = [];
function scratch(): string {
  const dir = mkdtempSync(join(tmpdir(), "nx-gw-sock-"));
  dirs.push(dir);
  return dir;
}
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("gatewaySocketProblem", () => {
  it("refuses a path that is not a socket", () => {
    const path = join(scratch(), "gateway.sock");
    writeFileSync(path, "");
    expect(gatewaySocketProblem(path)).toMatch(/not a socket/);
  });

  it("leaves a missing path to the usual connection error", () => {
    expect(gatewaySocketProblem(join(scratch(), "missing.sock"))).toBeNull();
  });

  it("accepts this account's own socket and calls through it", async () => {
    const path = join(scratch(), "gateway.sock");
    const server = net.createServer((sock) => {
      sock.on("data", () => sock.end(`${JSON.stringify({ id: 1, result: { aid: "aid:test" } })}\n`));
    });
    await new Promise<void>((resolve) => server.listen(path, resolve));
    try {
      expect(gatewaySocketProblem(path)).toBeNull();
      const gw = new NexusInboxGatewayClient({ socketPath: path });
      await expect(gw.call("whoami")).resolves.toEqual({ aid: "aid:test" });
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("does not connect when the path is not a socket", async () => {
    const path = join(scratch(), "gateway.sock");
    writeFileSync(path, "");
    const gw = new NexusInboxGatewayClient({ socketPath: path });
    await expect(gw.call("whoami")).rejects.toThrow(/not a socket/);
  });
});
