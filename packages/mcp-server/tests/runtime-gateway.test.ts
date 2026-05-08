/**
 * Isolated mode (Gateway + Signer Daemon) runtime tests.
 *
 * The `NexusInboxGatewayClient` accepts a `rpcTransport` injection
 * point, which we use to simulate a live Gateway without opening a
 * real Unix socket. Each test pre-programs a transport that returns
 * Gateway-shaped responses, then asserts:
 *
 *   - `list_my_agents` compresses `whoami` → one AgentSummary
 *   - `list_inbox` rejects a mismatched `agent_aid`
 *   - `read_message` Phase 2.5: gateway `read_message` →
 *     `unwrap_content_key` → local decrypt. Plaintext flows back
 *     without the X25519 private key ever entering the test process.
 *   - `reply_to_message` draft uses the unwrapped subject as the
 *     `Re:` pre-fill and threads correctly.
 *   - `send_text_message` draft returns the envelope without hitting
 *     the transport's `send_message`
 *   - `send_text_message` send goes through the Gateway with the
 *     `signature` field omitted (Gateway signs via the daemon) and a
 *     plausible encrypted envelope shape (enc:v1:... / x25519v1:...)
 *   - audit fires with the right `draft_body_hash` both before and
 *     after the send — matching hashes link draft → send in logs
 */

import { describe, expect, it, vi } from "vitest";
import {
  createGatewayRuntime,
  MODE_A_TOOL_ALLOWLIST,
} from "../src/runtime-gateway.js";
import { sha256Hex, type AuditEntry } from "../src/audit.js";

type FakeTransport = ReturnType<typeof vi.fn>;

function buildFakeTransport(
  responses: Record<string, unknown | ((params: Record<string, unknown>) => unknown)>,
): FakeTransport {
  return vi.fn(async (method: string, params: Record<string, unknown>) => {
    const spec = responses[method];
    if (spec === undefined) {
      throw new Error(`fake Gateway transport has no stub for method=${method}`);
    }
    if (typeof spec === "function") {
      return (spec as (p: Record<string, unknown>) => unknown)(params);
    }
    return spec;
  });
}

describe("Isolated mode tool allowlist (Phase 2.5: full read+send surface)", () => {
  it("includes the full read+send tool surface", () => {
    expect(MODE_A_TOOL_ALLOWLIST).toEqual([
      "list_my_agents",
      "list_inbox",
      "resolve_recipient",
      "read_message",
      "send_text_message",
      "reply_to_message",
    ]);
  });
});

describe("Isolated mode runtime (Gateway)", () => {
  const GATEWAY_WHOAMI = {
    aid: "aid:ai:self",
    did: "did:key:self-current",
    agent_ref: "Ops",
  };

  const RECIPIENT_BOB = {
    aid: "aid:ai:bob",
    did: "did:key:bob-current",
    label: "Bob",
    // Valid 32-byte X25519 public key (base64url) — not a real key,
    // just a length-correct stand-in for the wrap routine to accept.
    encryption_public_key: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
  };

  it("list_my_agents returns whoami as a one-element array", async () => {
    const rpcTransport = buildFakeTransport({
      whoami: GATEWAY_WHOAMI,
    });
    const { runtime } = await createGatewayRuntime({ rpcTransport });

    const result = await runtime.listMyAgents();

    expect(result.agents).toEqual([
      {
        aid: "aid:ai:self",
        did: "did:key:self-current",
        label: "Ops",
      },
    ]);
  });

  it("list_inbox rejects a mismatched agent_aid before calling the transport", async () => {
    const rpcTransport = buildFakeTransport({
      whoami: GATEWAY_WHOAMI,
    });
    const { runtime } = await createGatewayRuntime({ rpcTransport });

    await expect(
      runtime.listInbox({
        agent_aid: "aid:ai:someone-else",
        folder: "inbox",
      }),
    ).rejects.toThrow(/Isolated mode Gateway is bound to aid=aid:ai:self/);
    // Gateway bound check happens before the RPC call; transport was
    // only hit for whoami during construction.
    const calls = rpcTransport.mock.calls.map((call) => call[0]);
    expect(calls).toEqual(["whoami"]);
  });

  it("read_message goes through gateway.read_message + unwrap_content_key + local decrypt", async () => {
    // The dev-mode crypto path in `decryptSafely` returns the input
    // unchanged when the ciphertext isn't an `enc:v1:...` envelope, so
    // we can plumb plaintext fixtures through and assert the wiring
    // without standing up the full encrypt/wrap stack here.
    const rpcTransport = buildFakeTransport({
      whoami: GATEWAY_WHOAMI,
      read_message: {
        encrypted_content: "Hello from the integration test.",
        encrypted_key: "x25519v1:fake-eph:fake-salt:fake-iv:fake-ct",
        nonce: "fake-nonce",
        sender_did: "did:key:bob-current",
        recipient_did: "did:key:self-current",
        subject_encrypted: "Project status",
        thread_id: "thread-42",
      },
      unwrap_content_key: { content_key: "ck-deadbeef" },
    });
    const { runtime } = await createGatewayRuntime({ rpcTransport });

    const result = await runtime.readMessage({ message_id: "m-123" });

    expect(result).toMatchObject({
      message_id: "m-123",
      sender: { did: "did:key:bob-current" },
      recipient: { did: "did:key:self-current" },
      subject: "Project status",
      body: "Hello from the integration test.",
      attachments: [],
    });

    const methods = rpcTransport.mock.calls.map((call) => call[0]);
    expect(methods).toEqual(["whoami", "read_message", "unwrap_content_key"]);
    // The unwrap call carries through the gateway-returned encrypted_key
    // verbatim — the daemon (mocked here) returns the content_key.
    const unwrapCall = rpcTransport.mock.calls.find((c) => c[0] === "unwrap_content_key");
    expect(unwrapCall?.[1]).toEqual({
      encrypted_key: "x25519v1:fake-eph:fake-salt:fake-iv:fake-ct",
    });
  });

  it("reply_to_message draft uses the decrypted subject as Re: pre-fill and preserves thread_id", async () => {
    const audit: AuditEntry[] = [];
    const rpcTransport = buildFakeTransport({
      whoami: GATEWAY_WHOAMI,
      read_message: {
        encrypted_content: "Original body",
        encrypted_key: "x25519v1:fake",
        nonce: "n",
        sender_did: "did:key:bob-current",
        recipient_did: "did:key:self-current",
        subject_encrypted: "Status sync",
        thread_id: "thread-7",
      },
      unwrap_content_key: { content_key: "ck-1" },
      resolve_recipient: RECIPIENT_BOB,
    });
    const { runtime } = await createGatewayRuntime({
      rpcTransport,
      auditSink: (entry) => audit.push(entry),
    });

    const draft = await runtime.replyToMessage({
      incoming_message_id: "m-1",
      body_markdown: "ack — I'll take a look.",
      provider_hint: "claude-sonnet-4.5",
    });

    expect(draft).toMatchObject({
      mode: "draft",
      recipient_aid: "aid:ai:bob",
      recipient_did: "did:key:bob-current",
      subject: "Re: Status sync",
      thread_id: "thread-7",
      draft_body_hash: sha256Hex("ack — I'll take a look."),
    });

    expect(audit).toHaveLength(1);
    expect(audit[0]).toMatchObject({
      tool_name: "reply_to_message",
      mode: "draft",
      thread_id: "thread-7",
      message_id: "m-1",
    });
  });

  it("reply_to_message send (confirmed) routes back through the Gateway with thread_id preserved", async () => {
    const audit: AuditEntry[] = [];
    let capturedSendParams: Record<string, unknown> | null = null;
    const rpcTransport = buildFakeTransport({
      whoami: GATEWAY_WHOAMI,
      read_message: {
        encrypted_content: "old body",
        encrypted_key: "x25519v1:fake",
        nonce: "n",
        sender_did: "did:key:bob-current",
        recipient_did: "did:key:self-current",
        subject_encrypted: "Re: budget review",
        thread_id: "thread-99",
      },
      unwrap_content_key: { content_key: "ck-2" },
      resolve_recipient: RECIPIENT_BOB,
      send_message: (params: Record<string, unknown>) => {
        capturedSendParams = params;
        return { message_id: "m-REPLY-1", status: "delivered" };
      },
    });
    const { runtime } = await createGatewayRuntime({
      rpcTransport,
      auditSink: (entry) => audit.push(entry),
    });

    const sent = await runtime.replyToMessage({
      incoming_message_id: "m-1",
      body_markdown: "lgtm, shipping it.",
      mode: "send",
      confirmed_by_user: true,
    });

    expect(sent).toMatchObject({
      mode: "send",
      message_id: "m-REPLY-1",
      thread_id: "thread-99",
    });
    expect(capturedSendParams).not.toBeNull();
    const sendParams = capturedSendParams as {
      recipient_did: string;
      envelope: { metadata: { thread_id: string | null } };
    };
    expect(sendParams.recipient_did).toBe("did:key:bob-current");
    expect(sendParams.envelope.metadata.thread_id).toBe("thread-99");

    expect(audit).toHaveLength(1);
    expect(audit[0]).toMatchObject({
      tool_name: "reply_to_message",
      mode: "send",
      confirmed_by_user: true,
      message_id: "m-REPLY-1",
      thread_id: "thread-99",
    });
  });

  it("reply_to_message refuses mode='send' without confirmed_by_user", async () => {
    const rpcTransport = buildFakeTransport({
      whoami: GATEWAY_WHOAMI,
      read_message: {
        encrypted_content: "x",
        encrypted_key: "x25519v1:fake",
        nonce: "n",
        sender_did: "did:key:bob-current",
        subject_encrypted: "topic",
        thread_id: null,
      },
      unwrap_content_key: { content_key: "ck-3" },
      resolve_recipient: RECIPIENT_BOB,
    });
    const { runtime } = await createGatewayRuntime({ rpcTransport });

    await expect(
      runtime.replyToMessage({
        incoming_message_id: "m-1",
        body_markdown: "no confirm",
        mode: "send",
      }),
    ).rejects.toThrow(/confirmed_by_user=true/);

    const methods = rpcTransport.mock.calls.map((call) => call[0]);
    expect(methods).not.toContain("send_message");
  });

  it("send_text_message draft returns the envelope without a send_message RPC", async () => {
    const audit: AuditEntry[] = [];
    const rpcTransport = buildFakeTransport({
      whoami: GATEWAY_WHOAMI,
      resolve_recipient: RECIPIENT_BOB,
    });
    const { runtime } = await createGatewayRuntime({
      rpcTransport,
      auditSink: (entry) => audit.push(entry),
    });

    const result = await runtime.sendTextMessage({
      from_agent: "aid:ai:self",
      to: "aid:ai:bob",
      subject: "hi",
      body_markdown: "hello",
      provider_hint: "claude-sonnet-4.5",
    });

    expect(result.mode).toBe("draft");
    const methods = rpcTransport.mock.calls.map((call) => call[0]);
    expect(methods).toEqual(["whoami", "resolve_recipient"]);
    expect(audit).toHaveLength(1);
    expect(audit[0]).toMatchObject({
      tool_name: "send_text_message",
      mode: "draft",
      draft_body_hash: sha256Hex("hello"),
      recipient_aid: "aid:ai:bob",
      provider_hint: "claude-sonnet-4.5",
      credential_id: "(gateway-bound)",
    });
  });

  it("send_text_message send (confirmed) calls Gateway with unsigned envelope + records result message_id", async () => {
    const audit: AuditEntry[] = [];
    let capturedSendParams: Record<string, unknown> | null = null;
    const rpcTransport = buildFakeTransport({
      whoami: GATEWAY_WHOAMI,
      resolve_recipient: RECIPIENT_BOB,
      send_message: (params: Record<string, unknown>) => {
        capturedSendParams = params;
        return { message_id: "m-SENT-1", status: "delivered" };
      },
    });
    const { runtime } = await createGatewayRuntime({
      rpcTransport,
      auditSink: (entry) => audit.push(entry),
    });

    const result = await runtime.sendTextMessage({
      from_agent: "aid:ai:self",
      to: "aid:ai:bob",
      subject: "important update",
      body_markdown: "ship it",
      mode: "send",
      confirmed_by_user: true,
      provider_hint: "claude-sonnet-4.5",
    });

    expect(result).toMatchObject({
      mode: "send",
      message_id: "m-SENT-1",
      status: "delivered",
      draft_body_hash: sha256Hex("ship it"),
    });

    // Gateway saw send_message with recipient_did + envelope and
    // without a client-supplied signature (daemon signs).
    expect(capturedSendParams).not.toBeNull();
    const sendParams = capturedSendParams as {
      recipient_did: string;
      envelope: {
        encrypted_content: string;
        encrypted_key: string;
        nonce: string;
        signature?: string;
        metadata: { subject_encrypted: string };
      };
    };
    expect(sendParams.recipient_did).toBe("did:key:bob-current");
    expect(sendParams.envelope.signature).toBeUndefined();
    expect(sendParams.envelope.encrypted_content.startsWith("enc:v1:")).toBe(true);
    expect(sendParams.envelope.encrypted_key.startsWith("x25519v1:")).toBe(true);
    expect(sendParams.envelope.metadata.subject_encrypted.startsWith("enc:v1:")).toBe(true);

    // Audit: one entry, mode=send, confirmed, with matching hash.
    expect(audit).toHaveLength(1);
    expect(audit[0]).toMatchObject({
      tool_name: "send_text_message",
      mode: "send",
      confirmed_by_user: true,
      draft_body_hash: sha256Hex("ship it"),
      message_id: "m-SENT-1",
    });
  });

  it("send_text_message refuses mode='send' without confirmed_by_user", async () => {
    const rpcTransport = buildFakeTransport({
      whoami: GATEWAY_WHOAMI,
      resolve_recipient: RECIPIENT_BOB,
    });
    const { runtime } = await createGatewayRuntime({ rpcTransport });

    await expect(
      runtime.sendTextMessage({
        from_agent: "aid:ai:self",
        to: "aid:ai:bob",
        subject: "s",
        body_markdown: "b",
        mode: "send",
      }),
    ).rejects.toThrow(/confirmed_by_user=true/);

    // resolve_recipient *does* run (happens before the guard) but
    // send_message was never attempted.
    const methods = rpcTransport.mock.calls.map((call) => call[0]);
    expect(methods).not.toContain("send_message");
  });
});
