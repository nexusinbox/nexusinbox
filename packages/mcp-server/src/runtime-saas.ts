/**
 * Standard mode (SaaS / local keystore) runtime.
 *
 * Wires the tool catalog to `@nexusinbox/core`'s `NexusInboxApiClient`,
 * using a local keystore for long-lived key material and an in-memory
 * bearer/DPoP session that never leaks to the LLM or to disk.
 *
 * This is the primary Phase 1A runtime. Isolated mode (Gateway / Daemon) lands
 * later as a sibling adapter that exposes the same `NexusInboxMcpRuntime`
 * interface so the transport layer never needs to know which mode is
 * active.
 */

import type {
  NexusInboxApiClient as NexusInboxApiClientType,
  MessageContentResponse,
  MessageIndexEntry,
  MessageListResponse,
  RecipientResolution,
} from "@nexusinbox/core";
import {
  NexusInboxApiClient,
  exchangeAgentToken,
} from "@nexusinbox/core";
import {
  createAuditor,
  sha256Hex,
  type AuditSink,
  type Auditor,
} from "./audit.js";
import { decryptEnvelopeTextForRecipient } from "./decrypt.js";
import { loadOrActivateCredential, type LoadedCredential } from "./keystore.js";
import type {
  NexusInboxMcpRuntime,
  AgentSummary,
  DraftEnvelopeResult,
  InboxMessageSummary,
  ReadMessageResult,
  RecipientResolutionResult,
  SentMessageResult,
} from "./types.js";

export type SaasRuntimeConfig = {
  baseUrl: string;
  aid: string;
  credentialId: string;
  /** Required on first ever run; ignored once a keystore file exists for this credential. */
  enrollmentSecret?: string;
  /** Optional passphrase — when set, encrypts the keystore at rest. */
  passphrase?: string;
  /** Override the keystore directory (default: $AGENT_KEYSTORE_DIR or ~/.nexusinbox). */
  keystoreDir?: string;
  /** Injection point for tests. Defaults to stderr line-delimited JSON. */
  auditSink?: AuditSink;
};

/**
 * Build a Standard mode runtime ready to serve MCP tools. Call this once during
 * server startup — the token exchange happens eagerly so errors surface
 * before Claude Desktop even connects to the stdio socket.
 */
export async function createSaasRuntime(config: SaasRuntimeConfig): Promise<{
  runtime: NexusInboxMcpRuntime;
  credential: LoadedCredential;
}> {
  const credential = await loadOrActivateCredential({
    baseUrl: config.baseUrl,
    aid: config.aid,
    credentialId: config.credentialId,
    enrollmentSecret: config.enrollmentSecret,
    passphrase: config.passphrase,
    keystoreDir: config.keystoreDir,
  });

  // JWS Assertion → DPoP-bound access token exchange. Tokens stay in
  // closure scope; they must never be read by tool handlers, never land
  // on disk, and never leak into the LLM transport.
  //
  // The exchange closure is reused as the API client's `onUnauthorized`
  // callback. Long-running MCP server processes (Claude Desktop spawns
  // one per session and keeps it for hours) used to fail with
  // "401 unauthorized: agent token has expired" on the first call past
  // access-token TTL, because the original implementation captured the
  // token once at boot with no refresh. Now any 401 transparently
  // re-issues via JWS Assertion (the keystore is always available, so
  // refresh-token rotation is unnecessary) and retries the request.
  const issueTokens = async () => {
    const fresh = await exchangeAgentToken({
      baseUrl: config.baseUrl,
      aid: config.aid,
      credentialId: config.credentialId,
      signingPrivateKey: credential.signing.privateKey,
    });
    return { accessToken: fresh.access_token, dpop: fresh.dpop };
  };
  const initial = await issueTokens();
  const client = new NexusInboxApiClient({
    baseUrl: config.baseUrl,
    accessToken: initial.accessToken,
    dpop: initial.dpop,
    onUnauthorized: issueTokens,
  });

  const audit = createAuditor({
    aid: credential.aid,
    did: credential.did,
    credential_id: config.credentialId,
    sink: config.auditSink,
  });
  const runtime = buildRuntime(client, credential, config, audit);
  return { runtime, credential };
}

function buildRuntime(
  client: NexusInboxApiClientType,
  credential: LoadedCredential,
  config: SaasRuntimeConfig,
  audit: Auditor,
): NexusInboxMcpRuntime {
  return {
    async listMyAgents(): Promise<{ agents: AgentSummary[] }> {
      // In Standard mode a single keystore = a single aid, so "my agents" is
      // effectively the one this runtime is bound to. Listing the
      // underlying owner's other agents would require a human Cookie
      // session — explicitly out of scope for an agent-token runtime.
      const me = await client.resolveRecipient(config.aid);
      return {
        agents: [
          {
            aid: me.aid,
            did: me.did,
            label: me.label ?? null,
          },
        ],
      };
    },

    async listInbox(input) {
      // NOTE: the current @nexusinbox/core client does not yet surface
      // `page` / `per_page` parameters (the REST route does, but the SDK
      // wrapper was built for a simpler pattern). When the SDK adds
      // pagination params, thread them through here. For Phase 1A the
      // server returns page 1 / per_page defaults, which is enough for
      // most triage flows — the inbox isn't expected to be huge for an
      // early adopter.
      const response: MessageListResponse = await client.listMessages({
        agentDid: input.agent_aid,
        folder: input.folder ?? "inbox",
        status: input.status ?? "all",
      });
      const messages: InboxMessageSummary[] = response.messages.map(summarize);
      return {
        messages,
        total: response.total,
        page: response.page,
        per_page: response.per_page,
      };
    },

    async readMessage(input): Promise<ReadMessageResult> {
      const plain = await decryptIncoming(client, credential, input.message_id);
      audit({
        tool_name: "read_message",
        mode: "read",
        message_id: input.message_id,
      });
      // Attachment listing / decryption is a Phase 2 tool family; the
      // current @nexusinbox/core client does not expose
      // `listMessageAttachments`. Returning [] keeps the schema shape
      // stable without misleading the LLM.
      return {
        message_id: input.message_id,
        sender: plain.content.sender_did ? { did: plain.content.sender_did } : undefined,
        recipient: plain.content.recipient_did
          ? { did: plain.content.recipient_did }
          : undefined,
        subject: plain.subject,
        body: plain.body,
        attachments: [],
      };
    },

    async resolveRecipient(input): Promise<RecipientResolutionResult> {
      const resolved: RecipientResolution = await client.resolveRecipient(input.identifier);
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
      const recipient = await client.resolveRecipient(input.to);

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

      // mode === "send": require explicit human confirmation.
      requireConfirmation(input.confirmed_by_user, "send_text_message");
      const result = await sendViaClient(client, credential, {
        recipient,
        subject: input.subject,
        body: input.body_markdown,
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
      const plain = await decryptIncoming(
        client,
        credential,
        input.incoming_message_id,
      );
      if (!plain.content.sender_did) {
        throw new Error("incoming message has no sender_did — cannot draft a reply");
      }
      const recipient = await client.resolveRecipient(plain.content.sender_did);
      const subject =
        input.subject?.trim() || prefixReSubject(plain.subject);
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
          sender_aid: config.aid,
          recipient_aid: recipient.aid,
          recipient_did: recipient.did,
          subject,
          body_markdown: input.body_markdown,
          thread_id: threadId,
          draft_body_hash: body_hash,
        };
      }

      requireConfirmation(input.confirmed_by_user, "reply_to_message");
      const result = await sendViaClient(client, credential, {
        recipient,
        subject,
        body: input.body_markdown,
        threadId: threadId ?? undefined,
      });
      audit({
        tool_name: "reply_to_message",
        mode: "send",
        confirmed_by_user: true,
        draft_body_hash: body_hash,
        message_id: result.message_id,
        recipient_aid: recipient.aid,
        recipient_did: recipient.did,
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
 * Enforce the Phase 1B confirmation gate. The LLM host is expected to
 * show a prompt and echo back `confirmed_by_user: true`. A missing or
 * `false` value fails closed with a caller-readable message so any
 * Skill that naively flips `mode: "send"` without a confirmation ritual
 * immediately breaks in a debuggable way.
 */
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

/**
 * Decrypt an incoming message and return both the structured envelope
 * and the resolved plaintext. Shared between `read_message` and
 * `reply_to_message` so the subject pre-fill and the user-facing read
 * come from the same decryption call.
 */
async function decryptIncoming(
  client: NexusInboxApiClientType,
  credential: LoadedCredential,
  messageId: string,
): Promise<{
  content: MessageContentResponse;
  subject: string;
  body: string;
}> {
  const content = await client.readMessage(messageId);
  const { subject, body } = await decryptEnvelopeTextForRecipient({
    encrypted_content: content.encrypted_content,
    encrypted_key: content.encrypted_key,
    nonce: content.nonce,
    subject_encrypted: content.subject_encrypted ?? "",
    recipientPrivateKey: credential.encryption.privateKey,
  });
  return { content, subject, body };
}

function prefixReSubject(subject: string): string {
  const trimmed = subject.trim();
  if (!trimmed) return "Re: ";
  // Don't double-prefix — if the original already starts with Re:/RE:/re:
  // we keep it stable, mirroring common mail-client behaviour.
  if (/^re:\s*/i.test(trimmed)) return trimmed;
  return `Re: ${trimmed}`;
}

/**
 * Minimal recipient shape the E2E send path needs. Accepts both the
 * SDK's `RecipientResolution` (where `encryption_public_key` is
 * optional) and our tool-facing `RecipientResolutionResult` (where it
 * is required) — we validate at the boundary rather than widening the
 * tool-response type.
 */
type SendableRecipient = { did: string; encryption_public_key?: string };

async function sendViaClient(
  client: NexusInboxApiClientType,
  credential: LoadedCredential,
  args: {
    recipient: SendableRecipient;
    subject: string;
    body: string;
    threadId?: string;
  },
): Promise<{ message_id: string; status: string }> {
  const encryptionPublicKey = args.recipient.encryption_public_key;
  if (!encryptionPublicKey) {
    throw new Error(
      "recipient has no registered encryption_public_key — cannot build E2E envelope",
    );
  }
  const response = await client.sendTextMessage({
    senderDid: credential.did,
    recipientDid: args.recipient.did,
    recipientEncryptionPublicKey: encryptionPublicKey,
    senderSigningPrivateKey: credential.signing.privateKey,
    subject: args.subject,
    body: args.body,
    threadId: args.threadId,
  });
  return { message_id: response.message_id, status: response.status };
}

function summarize(m: MessageIndexEntry): InboxMessageSummary {
  return {
    message_id: m.id,
    sender_did: m.sender_did,
    subject: "(encrypted — call read_message to decrypt)",
    created_at: m.created_at,
    status: m.status,
    folder: m.folder,
  };
}

// Re-export the class for testing convenience.
export { NexusInboxApiClient };
