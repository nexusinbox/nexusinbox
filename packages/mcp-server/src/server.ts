/**
 * MCP stdio server wiring.
 *
 * Takes an already-bound `NexusInboxMcpRuntime` and registers each tool
 * from `TOOL_CATALOG` with the MCP SDK. Stdio transport is the default
 * because Claude Desktop / Cursor / Claude Code all consume stdio-mode
 * MCP servers; HTTP/SSE lands in Phase 3 (remote MCP).
 *
 * Phase 1A exposes only the 4 read-family tools. Phase 1B write tools
 * are registered but wired to the runtime's draft-only stubs so a
 * misconfigured runtime fails with a human-readable error instead of
 * silently bypassing the policy.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import type { DeploymentMode } from "./index.js";
import { TOOL_CATALOG } from "./tools.js";
import type { NexusInboxMcpRuntime, ToolDefinition } from "./types.js";

export type StartStdioServerInput = {
  runtime: NexusInboxMcpRuntime;
  activeMode: DeploymentMode;
  /** Optional subset of TOOL_CATALOG names to expose. Defaults to all. */
  enabledTools?: string[];
};

/**
 * Start the MCP stdio server. Blocks for the lifetime of the process.
 */
export async function startStdioServer(input: StartStdioServerInput): Promise<void> {
  const tools = filterTools(TOOL_CATALOG, input.enabledTools);
  const server = new Server(
    {
      name: "@nexusinbox/mcp-server",
      version: "0.1.0",
    },
    {
      capabilities: {
        tools: {},
      },
    },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: tools.map((tool) => ({
      name: tool.name,
      description: tool.description,
      inputSchema: tool.inputSchema as Record<string, unknown>,
    })),
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const name = request.params.name;
    const args = (request.params.arguments ?? {}) as Record<string, unknown>;
    const tool = tools.find((t) => t.name === name);
    if (!tool) {
      return errorResponse(`unknown tool: ${name}`);
    }

    try {
      const result = await dispatch(input.runtime, tool, args);
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return errorResponse(message);
    }
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);

  // Emit a one-line startup note on stderr so operators can tail the
  // logs without breaking the stdio protocol on stdout.
  process.stderr.write(
    `[nexusinbox-mcp] connected (mode=${input.activeMode}, tools=${tools.length})\n`,
  );
}

function filterTools(
  all: readonly ToolDefinition[],
  enabled?: string[],
): ToolDefinition[] {
  if (!enabled || enabled.length === 0) return [...all];
  const set = new Set(enabled);
  return all.filter((t) => set.has(t.name));
}

async function dispatch(
  runtime: NexusInboxMcpRuntime,
  tool: ToolDefinition,
  args: Record<string, unknown>,
): Promise<unknown> {
  switch (tool.name) {
    case "list_my_agents":
      return runtime.listMyAgents();
    case "list_inbox":
      return runtime.listInbox(args as Parameters<NexusInboxMcpRuntime["listInbox"]>[0]);
    case "read_message":
      return runtime.readMessage(
        args as Parameters<NexusInboxMcpRuntime["readMessage"]>[0],
      );
    case "resolve_recipient":
      return runtime.resolveRecipient(
        args as Parameters<NexusInboxMcpRuntime["resolveRecipient"]>[0],
      );
    case "send_text_message":
      return runtime.sendTextMessage(
        args as Parameters<NexusInboxMcpRuntime["sendTextMessage"]>[0],
      );
    case "reply_to_message":
      return runtime.replyToMessage(
        args as Parameters<NexusInboxMcpRuntime["replyToMessage"]>[0],
      );
    default:
      throw new Error(`tool ${tool.name} is not dispatchable yet`);
  }
}

function errorResponse(message: string): {
  isError: true;
  content: Array<{ type: "text"; text: string }>;
} {
  return {
    isError: true,
    content: [{ type: "text", text: message }],
  };
}
