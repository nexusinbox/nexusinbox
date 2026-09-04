import type { ToolDefinition } from "./types.js";

/**
 * Server-issued message ids are UUIDs. Declaring the shape in the schema
 * lets well-behaved clients reject junk early, and `validateToolArguments`
 * enforces it for everyone else before the id reaches a URL path (SaaS
 * mode) or the Gateway RPC (Mode A).
 */
export const UUID_PATTERN =
  "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$";

export const TOOL_CATALOG: ToolDefinition[] = [
  {
    name: "list_my_agents",
    description: "Return the caller's usable agents as stable aid + current did pairs.",
    phase: "phase1a",
    risk: "low",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {},
    },
  },
  {
    name: "list_inbox",
    description: "List inbox messages for an agent aid with optional folder / status filters.",
    phase: "phase1a",
    risk: "low",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["agent_aid"],
      properties: {
        agent_aid: { type: "string" },
        folder: { type: "string" },
        status: { type: "string" },
        page: { type: "integer", minimum: 1 },
        per_page: { type: "integer", minimum: 1, maximum: 100 },
      },
    },
  },
  {
    name: "read_message",
    description: "Read and decrypt one message so the assistant can reason over its plaintext.",
    phase: "phase1a",
    risk: "medium",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["message_id"],
      properties: {
        message_id: { type: "string", pattern: UUID_PATTERN },
      },
    },
  },
  {
    name: "resolve_recipient",
    description: "Resolve an aid or did into the current recipient did and encryption key.",
    phase: "phase1a",
    risk: "low",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["identifier"],
      properties: {
        identifier: { type: "string" },
      },
    },
  },
  {
    name: "send_text_message",
    description:
      "Compose a plaintext message envelope for NexusInbox. Default " +
      "mode='draft' returns the resolved envelope + draft_body_hash " +
      "without sending. mode='send' requires confirmed_by_user=true; " +
      "the assistant must surface a confirmation prompt to the human " +
      "before setting it. Pass provider_hint for audit visibility.",
    phase: "phase1b",
    risk: "high",
    requiresConfirmation: true,
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["from_agent", "to", "subject", "body_markdown"],
      properties: {
        from_agent: { type: "string" },
        to: { type: "string" },
        subject: { type: "string" },
        body_markdown: { type: "string" },
        mode: { type: "string", enum: ["draft", "send"], default: "draft" },
        confirmed_by_user: { type: "boolean" },
        provider_hint: { type: "string", maxLength: 128 },
      },
    },
  },
  {
    name: "reply_to_message",
    description:
      "Reply to an existing message by id. Subject auto-prefills as " +
      "'Re: <decrypted subject>' unless overridden. Default mode='draft' " +
      "returns the reply envelope; mode='send' requires confirmed_by_user=true.",
    phase: "phase1b",
    risk: "high",
    requiresConfirmation: true,
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["incoming_message_id", "body_markdown"],
      properties: {
        incoming_message_id: { type: "string", pattern: UUID_PATTERN },
        body_markdown: { type: "string" },
        subject: { type: "string" },
        mode: { type: "string", enum: ["draft", "send"], default: "draft" },
        confirmed_by_user: { type: "boolean" },
        provider_hint: { type: "string", maxLength: 128 },
      },
    },
  },
];

/**
 * Enforce the `pattern` constraints a tool's inputSchema declares.
 *
 * The low-level MCP SDK `Server` hands tool arguments through without
 * checking them against the advertised schema, so without this a client
 * could pass any string where the schema promises a UUID. Presence of
 * required fields is left to the runtime, which already reports missing
 * ids with its own error text.
 */
export function validateToolArguments(
  tool: ToolDefinition,
  args: Record<string, unknown>,
): void {
  const properties =
    (tool.inputSchema.properties as Record<string, { pattern?: string }> | undefined) ?? {};
  for (const [key, schema] of Object.entries(properties)) {
    if (!schema.pattern) continue;
    const value = args[key];
    if (value === undefined) continue;
    if (typeof value !== "string" || !new RegExp(schema.pattern).test(value)) {
      throw new Error(`${key} must match ${schema.pattern}`);
    }
  }
}

export function phase1aTools(): ToolDefinition[] {
  return TOOL_CATALOG.filter((tool) => tool.phase === "phase1a");
}

export function phase1bTools(): ToolDefinition[] {
  return TOOL_CATALOG.filter((tool) => tool.phase === "phase1b");
}
