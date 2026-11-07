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

type PropertySchema = {
  type?: "string" | "integer" | "boolean";
  pattern?: string;
  enum?: readonly unknown[];
  maxLength?: number;
  minimum?: number;
  maximum?: number;
};

/**
 * Enforce the constraints a tool's inputSchema declares: unknown
 * arguments (when `additionalProperties: false`), `type`, `enum`,
 * `pattern`, `maxLength`, `minimum` and `maximum`.
 *
 * The low-level MCP SDK `Server` hands tool arguments through without
 * checking them against the advertised schema. Checking only `pattern`
 * left `mode` fail-open — any value other than "draft" (say "preview" or
 * "SEND") took the send branch — and let `provider_hint` past its
 * 128-character cap into the audit log (review 2026-11-07). Presence of
 * required fields is left to the runtime, which reports missing ids with
 * its own error text; `null` is treated like an omitted optional field.
 */
export function validateToolArguments(
  tool: ToolDefinition,
  args: Record<string, unknown>,
): void {
  const schema = tool.inputSchema as {
    properties?: Record<string, PropertySchema>;
    additionalProperties?: boolean;
  };
  const properties = schema.properties ?? {};
  if (schema.additionalProperties === false) {
    for (const key of Object.keys(args)) {
      if (!Object.prototype.hasOwnProperty.call(properties, key)) {
        throw new Error(`unexpected argument: ${key}`);
      }
    }
  }
  for (const [key, prop] of Object.entries(properties)) {
    const value = args[key];
    if (value === undefined || value === null) continue;
    if (prop.type === "string" && typeof value !== "string") {
      throw new Error(`${key} must be a string`);
    }
    if (prop.type === "integer" && !Number.isInteger(value)) {
      throw new Error(`${key} must be an integer`);
    }
    if (prop.type === "boolean" && typeof value !== "boolean") {
      throw new Error(`${key} must be a boolean`);
    }
    if (prop.enum && !prop.enum.includes(value)) {
      throw new Error(`${key} must be one of: ${prop.enum.join(", ")}`);
    }
    if (typeof value === "string") {
      if (prop.maxLength !== undefined && value.length > prop.maxLength) {
        throw new Error(`${key} must be at most ${prop.maxLength} characters`);
      }
      if (prop.pattern && !new RegExp(prop.pattern).test(value)) {
        throw new Error(`${key} must match ${prop.pattern}`);
      }
    } else if (prop.pattern) {
      throw new Error(`${key} must match ${prop.pattern}`);
    }
    if (typeof value === "number") {
      if (prop.minimum !== undefined && value < prop.minimum) {
        throw new Error(`${key} must be >= ${prop.minimum}`);
      }
      if (prop.maximum !== undefined && value > prop.maximum) {
        throw new Error(`${key} must be <= ${prop.maximum}`);
      }
    }
  }
}

/**
 * `send_text_message` takes `from_agent` from the model, but the message
 * is always signed and sent as the agent this server is bound to. Refuse
 * a mismatching value instead of echoing it into the draft, where the
 * human confirming the send would read a sender that is not the real one.
 */
export function assertFromBoundAgent(
  fromAgent: string,
  bound: { aid: string; did: string },
): void {
  const value = fromAgent.trim();
  if (value !== bound.aid && value !== bound.did) {
    throw new Error(
      `from_agent must be the agent this server is bound to (${bound.aid}); got ${value || "(empty)"}`,
    );
  }
}

export function phase1aTools(): ToolDefinition[] {
  return TOOL_CATALOG.filter((tool) => tool.phase === "phase1a");
}

export function phase1bTools(): ToolDefinition[] {
  return TOOL_CATALOG.filter((tool) => tool.phase === "phase1b");
}
