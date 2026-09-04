import { describe, expect, it } from "vitest";
import { TOOL_CATALOG, UUID_PATTERN, validateToolArguments } from "../src/index.js";

const VALID_ID = "2b6d8a1e-0c4f-4b7e-9a1d-3c5e7f9b1d2e";

function tool(name: string) {
  const found = TOOL_CATALOG.find((t) => t.name === name);
  if (!found) throw new Error(`missing tool ${name}`);
  return found;
}

describe("validateToolArguments", () => {
  it("advertises the UUID shape for message ids", () => {
    const readProps = tool("read_message").inputSchema.properties as Record<string, { pattern?: string }>;
    const replyProps = tool("reply_to_message").inputSchema.properties as Record<
      string,
      { pattern?: string }
    >;
    expect(readProps.message_id.pattern).toBe(UUID_PATTERN);
    expect(replyProps.incoming_message_id.pattern).toBe(UUID_PATTERN);
  });

  it("accepts a well-formed UUID", () => {
    expect(() => validateToolArguments(tool("read_message"), { message_id: VALID_ID })).not.toThrow();
    expect(() =>
      validateToolArguments(tool("reply_to_message"), {
        incoming_message_id: VALID_ID.toUpperCase(),
        body_markdown: "hi",
      }),
    ).not.toThrow();
  });

  it("rejects ids that could escape the message route", () => {
    expect(() =>
      validateToolArguments(tool("read_message"), { message_id: "../auth/session" }),
    ).toThrow(/message_id/);
    expect(() =>
      validateToolArguments(tool("read_message"), { message_id: `${VALID_ID}/content` }),
    ).toThrow(/message_id/);
    expect(() =>
      validateToolArguments(tool("reply_to_message"), {
        incoming_message_id: "not-a-uuid",
        body_markdown: "hi",
      }),
    ).toThrow(/incoming_message_id/);
  });

  it("rejects non-string values for pattern fields", () => {
    expect(() => validateToolArguments(tool("read_message"), { message_id: 42 })).toThrow(
      /message_id/,
    );
  });

  it("leaves tools without pattern constraints alone", () => {
    expect(() =>
      validateToolArguments(tool("list_inbox"), { agent_aid: "aid:ai:anything goes" }),
    ).not.toThrow();
  });
});
