import { describe, expect, it } from "vitest";
import {
  buildManifest,
  createScaffoldRuntime,
  createRuntimeNotConfiguredError,
  phase1aTools,
  phase1bTools,
  TOOL_CATALOG,
} from "../src/index.js";

describe("@nexusinbox/mcp-server scaffold", () => {
  it("publishes the expected phase 1A tool names", () => {
    expect(phase1aTools().map((tool) => tool.name)).toEqual([
      "list_my_agents",
      "list_inbox",
      "read_message",
      "resolve_recipient",
    ]);
  });

  it("keeps write tools gated in phase 1B with draft mode", () => {
    const names = phase1bTools().map((tool) => tool.name);
    expect(names).toEqual(["send_text_message", "reply_to_message"]);

    for (const tool of phase1bTools()) {
      const modeProperty = (tool.inputSchema.properties as Record<string, unknown>).mode as
        | { default?: string }
        | undefined;
      expect(modeProperty?.default).toBe("draft");
      expect(tool.requiresConfirmation).toBe(true);
    }
  });

  it("builds a manifest with both deployment modes", () => {
    const manifest = buildManifest();
    expect(manifest.name).toBe("@nexusinbox/mcp-server");
    expect(manifest.deployment_modes).toEqual([
      "mode_a_gateway_daemon",
      "mode_b_saas_keystore",
    ]);
    expect(manifest.tools).toHaveLength(TOOL_CATALOG.length);
  });

  it("scaffold runtime fails loudly until wired", async () => {
    const runtime = createScaffoldRuntime();
    const expected = createRuntimeNotConfiguredError().message;
    await expect(runtime.listMyAgents()).rejects.toThrow(expected);
    await expect(runtime.readMessage({ message_id: "msg_123" })).rejects.toThrow(expected);
  });
});
