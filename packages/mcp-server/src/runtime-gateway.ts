/**
 * Isolated mode (self-hosted / Gateway + Signer Daemon) runtime.
 *
 * Value proposition: the agent's Ed25519 / X25519 private keys never
 * live in the MCP process. The LLM host sees MCP tool calls; the MCP
 * server only holds a Unix-socket RPC handle to a local Agent Gateway,
 * which in turn drives the Signer Daemon for crypto and forwards REST
 * to the NexusInbox API. Keys stay encrypted at rest (Argon2id +
 * XChaCha20-Poly1305) and only enter RAM inside the daemon.
 *
 * Shipped scope (Phase 2.5)
 * -------------------------
 * - `list_my_agents`     (via `whoami`)
 * - `list_inbox`         (via `list_inbox`)
 * - `resolve_recipient`  (via `resolve_recipient`)
 * - `send_text_message`  (builds the envelope locally without signing,
 *                         Gateway + Daemon sign and forward)
 * - `read_message`       (Gateway returns the encrypted envelope →
 *                         daemon `unwrap_content_key` recovers the
 *                         content_key → local AES-GCM decrypts the
 *                         subject + body. The X25519 private key stays
 *                         inside the daemon.)
 * - `reply_to_message`   (same `read_message` decrypt path for the
 *                         incoming leg, then the usual send flow.)
 *
 * The CLI picks which runtime to bind via env / flag, so swapping a
 * signer-daemon install for a plain keystore is a config change, not
 * a code change.
 */

import { encryptText, serializeEncryptedPayload } from "@nexusinbox/crypto";
import {
  NexusInboxGatewayClient,
  generateContentKey,
  wrapContentKeyForRecipient,
  type GatewayWhoAmI,
  type MessageContentResponse,
  type MessageListResponse,
  type RecipientResolution,
  type SendEnvelope,
} from "@nexusinbox/core";
import {
  createAuditor,
  sha256Hex,
  type AuditSink,
  type Auditor,
} from "./audit.js";
import { decryptEnvelopeTextWithContentKey } from "./decrypt.js";
import type {
  NexusInboxMcpRuntime,
  DraftEnvelopeResult,
  InboxMessageSummary,
  ReadMessageResult,
  RecipientResolutionResult,
  SentMessageResult,
} from "./types.js";

export type GatewayRuntimeConfig = {
  /** Default: `/tmp/nexusinbox-gateway.sock`. */
  socketPath?: string;
  /** Injection point for tests. Defaults to stderr line-delimited JSON. */
  auditSink?: AuditSink;
  /**
   * Optional override of the Gateway client transport (for tests).
   * Bypasses the real UDS entirely — the function receives `(method,
   * params)` and should return a parsed result object.
   */
  rpcTransport?: (method: string, params: Record<string, unknown>) => Promise<unknown>;
};

export type ModeARuntimeBundle = {
  runtime: NexusInboxMcpRuntime;
  whoami: GatewayWhoAmI;
  /** Tools that Isolated mode actually implements today; pass to the stdio server's `enabledTools`. */
  supportedTools: string[];
};

const MODE_A_SUPPORTED_TOOLS = [
  "list_my_agents",
  "list_inbox",
  "resolve_recipient",
  "read_message",
  "send_text_message",
  "reply_to_message",
] as const;

export async function createGatewayRuntime(
  config: GatewayRuntimeConfig = {},
): Promise<ModeARuntimeBundle> {
  const gw = new NexusInboxGatewayClient({
    socketPath: config.socketPath,
    rpcTransport: config.rpcTransport,
  });
  const whoami = await gw.whoami();

  const audit = createAuditor({
    aid: whoami.aid,
    did: whoami.did,
    // Isolated mode has no per-credential identifier visible to the MCP server
    // — the Gateway is bound to one credential internally. Record that
    // fact in the audit stream so a reader can tell the two modes apart
    // without guessing from the absence of the field.
    credential_id: "(gateway-bound)",
    sink: config.auditSink,
  });

  return {
    runtime: buildGatewayRuntime(gw, whoami, audit),
    whoami,
    supportedTools: [...MODE_A_SUPPORTED_TOOLS],
  };
}

function buildGatewayRuntime(
  gw: NexusInboxGatewayClient,
  whoami: GatewayWhoAmI,
  audit: Auditor,
): NexusInboxMcpRuntime {
  return {
    async listMyAgents() {
      return {
        agents: [
          {
            aid: whoami.aid,
            did: whoami.did,
            label: whoami.agent_ref ?? null,
          },
        ],
      };
    },

    async listInbox(input) {
      if (input.agent_aid && input.agent_aid !== whoami.aid) {
        throw new Error(
          `Isolated mode Gateway is bound to aid=${whoami.aid}; cannot list inbox for ${input.agent_aid}. ` +
            "Start a separate Gateway (or use Standard mode) for a different aid.",
        );
      }
      const response: MessageListResponse = await gw.listInbox({
        folder: input.folder ?? "inbox",
        status: input.status ?? "all",
      });
      const messages: InboxMessageSummary[] = response.messages.map((m) => ({
        message_id: m.id,
        sender_did: m.sender_did,
        subject: "(encrypted — call read_message to decrypt)",
        created_at: m.created_at,
        status: m.status,
        folder: m.folder,
      }));
      return {
        messages,
        total: response.total,
        page: response.page,
        per_page: response.per_page,
      };
    },

    async readMessage(input): Promise<ReadMessageResult> {
      const plain = await decryptIncomingViaGateway(gw, input.message_id);
      return {
        message_id: input.message_id,
        sender: plain.content.sender_did ? { did: plain.content.sender_did } : undefined,
        recipient: plain.content.recipient_did
          ? { did: plain.content.recipient_did }
          : undefined,
        subject: plain.subject,
        body: plain.body,
        // Attachment listing / decryption is Phase 2; the Gateway does
        // not yet expose a list_attachments RPC. Returning [] keeps the
        // schema stable without misleading the LLM.
        attachments: [],
      };
    },

    async resolveRecipient(input): Promise<RecipientResolutionResult> {
      const resolved: RecipientResolution = await gw.resolveRecipient(input.identifier);
      return {
        aid: resolved.aid,
        did: resolved.did,
        label: resolved.label ?? null,
        encryption_public_key: resolved.encryption_public_key ?? "",
      };
    },

    async sendTextMessage(input): Promise<DraftEnvelopeResult | SentMessageResult> {
      const mode = input.mode ?? "draft";
      const body_hash = sha256Hex(input.body_markdown);
      const recipient = await gw.resolveRecipient(input.to);

      if (mode === "draft") {
        audit({
          tool_name: "send_text_message",
          mode: "draft",
          draft_body_hash: body_hash,
          recipient_aid: recipient.aid,
          recipient_did: recipient.did,
          provider_hint: input.provider_hint,
        });
        return {
          mode: "draft",
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
      const recipientPublicKey = recipient.encryption_public_key;
      if (!recipientPublicKey) {
        throw new Error(
          "recipient has no registered encryption_public_key — cannot build E2E envelope",
        );
      }
      const envelope = await buildUnsignedEnvelope({
        subject: input.subject,
        body: input.body_markdown,
        recipientEncPubKey: recipientPublicKey,
      });
      const result = await gw.sendMessage({
        recipientDid: recipient.did,
        envelope,
      });
      audit({
        tool_name: "send_text_message",
        mode: "send",
        confirmed_by_user: true,
        draft_body_hash: body_hash,
        recipient_aid: recipient.aid,
        recipient_did: recipient.did,
        message_id: result.message_id,
        provider_hint: input.provider_hint,
      });
      return {
        mode: "send",
        message_id: result.message_id,
        status: result.status,
        thread_id: null,
        draft_body_hash: body_hash,
      };
    },

    async replyToMessage(input): Promise<DraftEnvelopeResult | SentMessageResult> {
      const mode = input.mode ?? "draft";
      const plain = await decryptIncomingViaGateway(gw, input.incoming_message_id);
      if (!plain.content.sender_did) {
        throw new Error("incoming message has no sender_did — cannot draft a reply");
      }
      const recipient = await gw.resolveRecipient(plain.content.sender_did);
      const subject = input.subject?.trim() || prefixReSubject(plain.subject);
      const threadId = plain.content.thread_id ?? null;
      const body_hash = sha256Hex(input.body_markdown);

      if (mode === "draft") {
        audit({
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
          mode: "draft",
          sender_aid: whoami.aid,
          recipient_aid: recipient.aid,
          recipient_did: recipient.did,
          subject,
          body_markdown: input.body_markdown,
          thread_id: threadId,
          draft_body_hash: body_hash,
        };
      }

      requireConfirmation(input.confirmed_by_user, "reply_to_message");
      const recipientPublicKey = recipient.encryption_public_key;
      if (!recipientPublicKey) {
        throw new Error(
          "recipient has no registered encryption_public_key — cannot build E2E envelope",
        );
      }
      const envelope = await buildUnsignedEnvelope({
        subject,
        body: input.body_markdown,
        recipientEncPubKey: recipientPublicKey,
        threadId,
      });
      const result = await gw.sendMessage({
        recipientDid: recipient.did,
        envelope,
      });
      audit({
        tool_name: "reply_to_message",
        mode: "send",
        confirmed_by_user: true,
        draft_body_hash: body_hash,
        recipient_aid: recipient.aid,
        recipient_did: recipient.did,
        message_id: result.message_id,
        thread_id: threadId,
        provider_hint: input.provider_hint,
      });
      return {
        mode: "send",
        message_id: result.message_id,
        status: result.status,
        thread_id: threadId,
        draft_body_hash: body_hash,
      };
    },
  };
}

/**
 * Isolated mode read helper: fetch the encrypted envelope, ask the daemon
 * (via Gateway) to unwrap the content_key, then decrypt locally. The
 * MCP process never sees the recipient's X25519 private key — only the
 * short-lived content_key plaintext, which is forgotten once this
 * promise resolves.
 */
async function decryptIncomingViaGateway(
  gw: NexusInboxGatewayClient,
  messageId: string,
): Promise<{
  content: MessageContentResponse;
  subject: string;
  body: string;
}> {
  const content = await gw.readMessage(messageId);
  const contentKey = await gw.unwrapContentKey(content.encrypted_key);
  const { subject, body } = await decryptEnvelopeTextWithContentKey({
    encrypted_content: content.encrypted_content,
    subject_encrypted: content.subject_encrypted ?? "",
    contentKey,
  });
  return { content, subject, body };
}

function prefixReSubject(subject: string): string {
  const trimmed = subject.trim();
  if (!trimmed) return "Re: ";
  if (/^re:\s*/i.test(trimmed)) return trimmed;
  return `Re: ${trimmed}`;
}

function requireConfirmation(
  flag: boolean | undefined,
  toolName: string,
): asserts flag {
  if (flag !== true) {
    throw new Error(
      `${toolName}: mode='send' requires confirmed_by_user=true. ` +
        "The LLM host must surface a confirmation prompt to the human " +
        "before flipping this flag.",
    );
  }
}

async function buildUnsignedEnvelope(args: {
  subject: string;
  body: string;
  recipientEncPubKey: string;
  threadId?: string | null;
}): Promise<Omit<SendEnvelope, "signature">> {
  const contentKey = generateContentKey();
  const encSubject = await encryptText(args.subject, contentKey);
  const encBody = await encryptText(args.body, contentKey);
  const encKey = await wrapContentKeyForRecipient(contentKey, args.recipientEncPubKey);
  return {
    encrypted_content: serializeEncryptedPayload(encBody),
    encrypted_key: encKey,
    nonce: encBody.iv,
    metadata: {
      subject_encrypted: serializeEncryptedPayload(encSubject),
      thread_id: args.threadId ?? null,
      content_type: "text/plain",
      has_attachments: false,
    },
  };
}

export const MODE_A_TOOL_ALLOWLIST: readonly string[] = MODE_A_SUPPORTED_TOOLS;
