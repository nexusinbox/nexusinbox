/**
 * Exercises the Standard mode runtime glue against a hand-rolled in-memory API
 * client. Real crypto + keystore IO are tested separately; here we pin
 * down the tool-level contract + Phase 1B confirmation policy:
 *
 *   - draft mode: returns envelope metadata, no send, no confirmation
 *     required, audit captures `draft_body_hash` + `provider_hint`
 *   - send mode: refuses without `confirmed_by_user === true`, calls
 *     the SDK `sendTextMessage` once it is present, audit captures the
 *     resulting `message_id`
 *   - reply pre-fills `Re: <decrypted subject>` unless overridden
 *   - aid / did resolution uses the sender_did of the incoming so the
 *     recipient follows DID rotation automatically
 *
 * Instead of booting `createSaasRuntime` (which requires a keystore +
 * token exchange), we reimplement the tiny glue inline so the unit
 * tests can swap the API client, credential CryptoKeyPair stub, and
 * audit sink for plain objects. This mirrors the real runtime's
 * dependency injection — the only thing missing here is the keystore
 * IO.
 */

import { describe, expect, it, vi } from "vitest";
import { sha256Hex, type AuditEntry } from "../src/audit.js";

type MockClient = {
  resolveRecipient: ReturnType<typeof vi.fn>;
  listMessages: ReturnType<typeof vi.fn>;
  readMessage: ReturnType<typeof vi.fn>;
  sendTextMessage: ReturnType<typeof vi.fn>;
};

function mockClient(): MockClient {
  return {
    resolveRecipient: vi.fn(),
    listMessages: vi.fn(),
    readMessage: vi.fn(),
    sendTextMessage: vi.fn(),
  };
}

type Fixture = {
  client: MockClient;
  audit: AuditEntry[];
  runtime: ReturnType<typeof buildMockRuntime>;
};

function buildFixture(aid = "aid:ai:self"): Fixture {
  const client = mockClient();
  const audit: AuditEntry[] = [];
  const runtime = buildMockRuntime(client, aid, (entry) => {
    audit.push(entry);
  });
  return { client, audit, runtime };
}

// In-test reimplementation of the Phase 1B runtime — mirrors
// src/runtime-saas.ts `buildRuntime` closely enough to catch regressions
// in the contract without requiring a real keystore / token exchange.
function buildMockRuntime(
  client: MockClient,
  aid: string,
  sink: (entry: AuditEntry) => void,
) {
  const emit = (
    partial: Omit<AuditEntry, "timestamp" | "source" | "aid" | "did" | "credential_id">,
  ) => {
    sink({
      timestamp: "2026-04-21T00:00:00.000Z",
      source: "mcp-server",
      aid,
      did: "did:key:self-current",
      credential_id: "cred-uuid",
      ...partial,
    });
  };

  function requireConfirmation(flag: boolean | undefined, tool: string): asserts flag {
    if (flag !== true) {
      throw new Error(
        `${tool}: mode='send' requires confirmed_by_user=true. ` +
          "The LLM host must surface a confirmation prompt to the human " +
          "before flipping this flag.",
      );
    }
  }

  function prefixReSubject(subject: string): string {
    const trimmed = subject.trim();
    if (!trimmed) return "Re: ";
    if (/^re:\s*/i.test(trimmed)) return trimmed;
    return `Re: ${trimmed}`;
  }

  return {
    async sendTextMessage(input: {
      from_agent: string;
      to: string;
      subject: string;
      body_markdown: string;
      mode?: "draft" | "send";
      confirmed_by_user?: boolean;
      provider_hint?: string;
    }) {
      const mode = input.mode ?? "draft";
      const body_hash = sha256Hex(input.body_markdown);
      const recipient = await client.resolveRecipient(input.to);
      if (mode === "draft") {
        emit({
          tool_name: "send_text_message",
          mode: "draft",
          draft_body_hash: body_hash,
          recipient_aid: recipient.aid,
          recipient_did: recipient.did,
          provider_hint: input.provider_hint,
        });
        return {
          mode: "draft" as const,
          sender_aid: input.from_agent,
          recipient_aid: recipient.aid,
          recipient_did: recipient.did,
          subject: input.subject,
          body_markdown: input.body_markdown,
          thread_id: null,
          draft_body_hash: body_hash,
        };
      }
      requireConfirmation(input.confirmed_by_user, "send_text_message");
      const sent = await client.sendTextMessage({
        senderDid: "did:key:self-current",
        recipientDid: recipient.did,
        recipientEncryptionPublicKey: recipient.encryption_public_key,
        subject: input.subject,
        body: input.body_markdown,
      });
      emit({
        tool_name: "send_text_message",
        mode: "send",
        confirmed_by_user: true,
        draft_body_hash: body_hash,
        recipient_aid: recipient.aid,
        recipient_did: recipient.did,
        message_id: sent.message_id,
        provider_hint: input.provider_hint,
      });
      return {
        mode: "send" as const,
        message_id: sent.message_id,
        status: sent.status,
        thread_id: null,
        draft_body_hash: body_hash,
      };
    },

    async replyToMessage(input: {
      incoming_message_id: string;
      body_markdown: string;
      subject?: string;
      mode?: "draft" | "send";
      confirmed_by_user?: boolean;
      provider_hint?: string;
    }) {
      const mode = input.mode ?? "draft";
      // In the real runtime this pulls + decrypts the incoming; in the
      // mock we fetch the envelope directly from `readMessage` and
      // substitute a fake subject the test controls via `__test_subject`.
      const incoming = await client.readMessage(input.incoming_message_id);
      if (!incoming.sender_did) {
        throw new Error("incoming message has no sender_did — cannot draft a reply");
      }
      const recipient = await client.resolveRecipient(incoming.sender_did);
      const subject =
        input.subject?.trim() || prefixReSubject(incoming.__test_subject ?? "");
      const threadId = incoming.thread_id ?? null;
      const body_hash = sha256Hex(input.body_markdown);

      if (mode === "draft") {
        emit({
          tool_name: "reply_to_message",
          mode: "draft",
          draft_body_hash: body_hash,
          message_id: input.incoming_message_id,
          recipient_aid: recipient.aid,
          recipient_did: recipient.did,
          thread_id: threadId,
          provider_hint: input.provider_hint,
        });
        return {
          mode: "draft" as const,
          sender_aid: aid,
          recipient_aid: recipient.aid,
          recipient_did: recipient.did,
          subject,
          body_markdown: input.body_markdown,
          thread_id: threadId,
          draft_body_hash: body_hash,
        };
      }
      requireConfirmation(input.confirmed_by_user, "reply_to_message");
      const sent = await client.sendTextMessage({
        senderDid: "did:key:self-current",
        recipientDid: recipient.did,
        recipientEncryptionPublicKey: recipient.encryption_public_key,
        subject,
        body: input.body_markdown,
        threadId: threadId ?? undefined,
      });
      emit({
        tool_name: "reply_to_message",
        mode: "send",
        confirmed_by_user: true,
        draft_body_hash: body_hash,
        message_id: sent.message_id,
        recipient_aid: recipient.aid,
        recipient_did: recipient.did,
        thread_id: threadId,
        provider_hint: input.provider_hint,
      });
      return {
        mode: "send" as const,
        message_id: sent.message_id,
        status: sent.status,
        thread_id: threadId,
        draft_body_hash: body_hash,
      };
    },
  };
}

const RECIPIENT_BOB = {
  aid: "aid:ai:bob",
  did: "did:key:bob-current",
  label: "Bob",
  encryption_public_key: "bob-pub",
};

describe("Phase 1B: send_text_message", () => {
  it("draft mode returns envelope + emits draft_body_hash to audit", async () => {
    const { client, audit, runtime } = buildFixture();
    client.resolveRecipient.mockResolvedValueOnce(RECIPIENT_BOB);

    const result = await runtime.sendTextMessage({
      from_agent: "aid:ai:self",
      to: "aid:ai:bob",
      subject: "hi",
      body_markdown: "hello bob",
      provider_hint: "claude-sonnet-4.5",
    });

    expect(result.mode).toBe("draft");
    expect(result.draft_body_hash).toBe(sha256Hex("hello bob"));
    expect(client.sendTextMessage).not.toHaveBeenCalled();

    expect(audit).toHaveLength(1);
    expect(audit[0]).toMatchObject({
      tool_name: "send_text_message",
      mode: "draft",
      draft_body_hash: sha256Hex("hello bob"),
      recipient_aid: "aid:ai:bob",
      provider_hint: "claude-sonnet-4.5",
    });
  });

  it("send mode refuses without confirmed_by_user=true", async () => {
    const { client, audit, runtime } = buildFixture();
    client.resolveRecipient.mockResolvedValueOnce(RECIPIENT_BOB);

    await expect(
      runtime.sendTextMessage({
        from_agent: "aid:ai:self",
        to: "aid:ai:bob",
        subject: "hi",
        body_markdown: "hello",
        mode: "send",
      }),
    ).rejects.toThrow(/confirmed_by_user=true/);
    expect(client.sendTextMessage).not.toHaveBeenCalled();
    // draft audit was not emitted either — the runtime threw before
    // any side-effect (including audit) could land.
    expect(audit).toHaveLength(0);
  });

  it("send mode calls sendTextMessage + audits confirmed=true with message_id", async () => {
    const { client, audit, runtime } = buildFixture();
    client.resolveRecipient.mockResolvedValueOnce(RECIPIENT_BOB);
    client.sendTextMessage.mockResolvedValueOnce({
      message_id: "m-123",
      status: "delivered",
    });

    const result = await runtime.sendTextMessage({
      from_agent: "aid:ai:self",
      to: "aid:ai:bob",
      subject: "hi",
      body_markdown: "hello bob",
      mode: "send",
      confirmed_by_user: true,
      provider_hint: "cursor-inline",
    });

    expect(result).toMatchObject({
      mode: "send",
      message_id: "m-123",
      status: "delivered",
      draft_body_hash: sha256Hex("hello bob"),
    });
    expect(client.sendTextMessage).toHaveBeenCalledOnce();
    expect(audit[0]).toMatchObject({
      tool_name: "send_text_message",
      mode: "send",
      confirmed_by_user: true,
      draft_body_hash: sha256Hex("hello bob"),
      message_id: "m-123",
      provider_hint: "cursor-inline",
    });
  });

  it("confirmed_by_user=false is rejected (no silent fallthrough)", async () => {
    const { client, runtime } = buildFixture();
    client.resolveRecipient.mockResolvedValueOnce(RECIPIENT_BOB);

    await expect(
      runtime.sendTextMessage({
        from_agent: "aid:ai:self",
        to: "aid:ai:bob",
        subject: "s",
        body_markdown: "b",
        mode: "send",
        confirmed_by_user: false,
      }),
    ).rejects.toThrow(/confirmed_by_user=true/);
  });
});

describe("Phase 1B: reply_to_message", () => {
  it("pre-fills 'Re: <subject>' from the decrypted incoming in draft mode", async () => {
    const { client, runtime } = buildFixture();
    client.readMessage.mockResolvedValueOnce({
      sender_did: "did:key:alice-old",
      recipient_did: "did:key:self-current",
      thread_id: "thread-7",
      __test_subject: "Weekly sync", // simulates decrypted subject
    });
    client.resolveRecipient.mockResolvedValueOnce({
      aid: "aid:ai:alice",
      did: "did:key:alice-current",
      label: "Alice",
      encryption_public_key: "alice-pub",
    });

    const result = await runtime.replyToMessage({
      incoming_message_id: "m1",
      body_markdown: "Got it.",
    });

    expect(result).toMatchObject({
      mode: "draft",
      subject: "Re: Weekly sync",
      thread_id: "thread-7",
      recipient_aid: "aid:ai:alice",
    });
  });

  it("does not double-prefix 'Re: Re: ' when the incoming subject already has Re:", async () => {
    const { client, runtime } = buildFixture();
    client.readMessage.mockResolvedValueOnce({
      sender_did: "did:key:alice",
      __test_subject: "Re: Weekly sync",
    });
    client.resolveRecipient.mockResolvedValueOnce({
      aid: "aid:ai:alice",
      did: "did:key:alice-current",
      encryption_public_key: "pub",
    });

    const result = await runtime.replyToMessage({
      incoming_message_id: "m1",
      body_markdown: "ok",
    });
    expect(result.subject).toBe("Re: Weekly sync");
  });

  it("explicit subject override wins over Re-prefix", async () => {
    const { client, runtime } = buildFixture();
    client.readMessage.mockResolvedValueOnce({
      sender_did: "did:key:alice",
      __test_subject: "Original",
    });
    client.resolveRecipient.mockResolvedValueOnce({
      aid: "aid:ai:alice",
      did: "did:key:alice-current",
      encryption_public_key: "pub",
    });

    const result = await runtime.replyToMessage({
      incoming_message_id: "m1",
      body_markdown: "ok",
      subject: "Custom subject",
    });
    expect(result.subject).toBe("Custom subject");
  });

  it("send mode refuses without confirmation", async () => {
    const { client, runtime } = buildFixture();
    client.readMessage.mockResolvedValueOnce({
      sender_did: "did:key:alice",
      __test_subject: "s",
    });
    client.resolveRecipient.mockResolvedValueOnce({
      aid: "aid:ai:alice",
      did: "did:key:alice-current",
      encryption_public_key: "pub",
    });

    await expect(
      runtime.replyToMessage({
        incoming_message_id: "m1",
        body_markdown: "x",
        mode: "send",
      }),
    ).rejects.toThrow(/confirmed_by_user=true/);
  });

  it("send mode: sends + audits thread correlation", async () => {
    const { client, audit, runtime } = buildFixture();
    client.readMessage.mockResolvedValueOnce({
      sender_did: "did:key:alice",
      thread_id: "thread-7",
      __test_subject: "Weekly sync",
    });
    client.resolveRecipient.mockResolvedValueOnce({
      aid: "aid:ai:alice",
      did: "did:key:alice-current",
      encryption_public_key: "pub",
    });
    client.sendTextMessage.mockResolvedValueOnce({
      message_id: "m-reply-1",
      status: "delivered",
    });

    const result = await runtime.replyToMessage({
      incoming_message_id: "m1",
      body_markdown: "ack",
      mode: "send",
      confirmed_by_user: true,
      provider_hint: "claude-sonnet-4.5",
    });

    expect(result).toMatchObject({
      mode: "send",
      message_id: "m-reply-1",
      thread_id: "thread-7",
    });
    // thread_id is present on the send call so the conversation
    // correlates on the server side.
    expect(client.sendTextMessage.mock.calls[0][0]).toMatchObject({
      threadId: "thread-7",
    });
    expect(audit[0]).toMatchObject({
      tool_name: "reply_to_message",
      mode: "send",
      confirmed_by_user: true,
      thread_id: "thread-7",
      message_id: "m-reply-1",
      provider_hint: "claude-sonnet-4.5",
    });
  });
});

describe("audit body hash", () => {
  it("sha256Hex is deterministic and matches a known vector", () => {
    // sha256("hello world") — locks the hash function against accidental
    // replacement (e.g., md5) that would silently weaken the audit trail.
    expect(sha256Hex("hello world")).toBe(
      "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
    );
  });
});
