import { TOOL_CATALOG } from "./tools.js";
import type { NexusInboxMcpRuntime, ToolDefinition } from "./types.js";

export type DeploymentMode = "mode_a_gateway_daemon" | "mode_b_saas_keystore";

export type McpServerManifest = {
  name: string;
  version: string;
  /** Deployment modes the server is *capable* of running under. */
  deployment_modes: DeploymentMode[];
  /** The mode the server is *actually* running under, once a runtime is bound. */
  active_mode?: DeploymentMode;
  tools: ToolDefinition[];
};

export function buildManifest(active_mode?: DeploymentMode): McpServerManifest {
  return {
    name: "@nexusinbox/mcp-server",
    version: "0.1.0",
    deployment_modes: ["mode_a_gateway_daemon", "mode_b_saas_keystore"],
    ...(active_mode ? { active_mode } : {}),
    tools: TOOL_CATALOG,
  };
}

export function createRuntimeNotConfiguredError(): Error {
  return new Error(
    "NexusInbox MCP runtime is not configured yet. This scaffold defines the tool surface only.",
  );
}

export function createScaffoldRuntime(): NexusInboxMcpRuntime {
  const notConfigured = async () => {
    throw createRuntimeNotConfiguredError();
  };

  return {
    listMyAgents: notConfigured,
    listInbox: notConfigured,
    readMessage: notConfigured,
    resolveRecipient: notConfigured,
    sendTextMessage: notConfigured,
    replyToMessage: notConfigured,
  };
}

export * from "./tools.js";
export * from "./types.js";
