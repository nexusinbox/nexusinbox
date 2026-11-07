import { describe, expect, it } from "vitest";
import {
  TOOL_CATALOG,
  UUID_PATTERN,
  assertFromBoundAgent,
  validateToolArguments,
} from "../src/index.js";

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

describe("validateToolArguments: full schema enforcement", () => {
  // Regression (review 2026-11-07): only `pattern` was checked, so `mode`
  // was fail-open (anything but "draft" took the send branch) and
  // provider_hint could exceed its 128-character cap.
  const send = () => tool("send_text_message");
  const base = {
    from_agent: "aid:ai:self",
    to: "aid:ai:bob",
    subject: "hi",
    body_markdown: "hello",
  };

  it("accepts the declared enum values and rejects anything else", () => {
    expect(() => validateToolArguments(send(), { ...base, mode: "draft" })).not.toThrow();
    expect(() => validateToolArguments(send(), { ...base, mode: "send" })).not.toThrow();
    for (const mode of ["preview", "SEND", "", "draft "]) {
      expect(() => validateToolArguments(send(), { ...base, mode }), mode).toThrow(/mode/);
    }
  });

  it("enforces maxLength, types and numeric bounds", () => {
    expect(() =>
      validateToolArguments(send(), { ...base, provider_hint: "x".repeat(129) }),
    ).toThrow(/provider_hint/);
    expect(() =>
      validateToolArguments(send(), { ...base, confirmed_by_user: "true" }),
    ).toThrow(/confirmed_by_user/);
    expect(() =>
      validateToolArguments(tool("list_inbox"), { agent_aid: "aid:ai:x", per_page: 101 }),
    ).toThrow(/per_page/);
    expect(() =>
      validateToolArguments(tool("list_inbox"), { agent_aid: "aid:ai:x", page: 0 }),
    ).toThrow(/page/);
    expect(() =>
      validateToolArguments(tool("list_inbox"), { agent_aid: "aid:ai:x", page: "2" }),
    ).toThrow(/page/);
  });

  it("rejects arguments the schema does not declare", () => {
    expect(() => validateToolArguments(send(), { ...base, cc: "aid:ai:eve" })).toThrow(
      /unexpected argument: cc/,
    );
  });

  it("treats null like an omitted optional argument", () => {
    expect(() =>
      validateToolArguments(send(), { ...base, mode: null, provider_hint: null }),
    ).not.toThrow();
  });
});

describe("assertFromBoundAgent", () => {
  const bound = { aid: "aid:ai:self", did: "did:key:zSelf" };
  it("accepts the bound aid or did", () => {
    expect(() => assertFromBoundAgent("aid:ai:self", bound)).not.toThrow();
    expect(() => assertFromBoundAgent(" did:key:zSelf ", bound)).not.toThrow();
  });
  it("refuses any other agent", () => {
    expect(() => assertFromBoundAgent("aid:ai:other", bound)).toThrow(/from_agent/);
    expect(() => assertFromBoundAgent("", bound)).toThrow(/from_agent/);
  });
});
