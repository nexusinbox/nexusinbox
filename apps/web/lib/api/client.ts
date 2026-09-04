import {
  AuthSessionResponse,
  AuthVerifyRequest,
  AuthVerifyResponse,
  AuthLogoutResponse,
  UpdateProfileRequest,
  AgentsResponse,
  BlocksResponse,
  ContactEntry,
  ContactsResponse,
  CreateAgentRequest,
  CreateAgentResponse,
  AgentCredential,
  AgentCredentialsResponse,
  CreateAgentCredentialRequest,
  RecipientResolutionResponse,
  AgentAuthTokenResponse,
  AgentAuthRefreshRequest,
  UpdateAgentRequest,
  UpdateAgentResponse,
  BlockFromMessageRequest,
  BlockFromMessageResponse,
  CreateBlockRequest,
  CreateBlockResponse,
  CreateContactRequest,
  CreateContactResponse,
  UpdateContactRequest,
  MessageContentResponse,
  MessageListQuery,
  MessageListResponse,
  MessagePriority,
  MessageStatus,
  StatusResponse,
  AuditLogQuery,
  AuditLogResponse,
  EmergencyShutdownResponse,
  AutoReplyPolicyResponse,
  PutAutoReplyPolicyRequest,
  MarkAutoReplySentRequest,
  MarkAutoReplySentResponse,
  CreateAttachmentIntentRequest,
  CreateAttachmentIntentResponse,
  CompleteAttachmentResponse,
  ListMessageAttachmentsResponse,
  AttachmentDownloadUrlResponse,
  OutboundAttachmentRef,
} from "./types";

export type ApiClientOptions = {
  baseUrl?: string;
  bearerToken?: string;
};

export class ApiError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

const DEFAULT_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL ?? "/api";

function toSearchParams(query: MessageListQuery): URLSearchParams {
  const params = new URLSearchParams({ agent_did: query.agentDid });

  if (query.status) params.set("status", query.status);
  if (query.priority) params.set("priority", query.priority);
  if (query.folder) params.set("folder", query.folder);
  if (query.threadId) params.set("thread_id", query.threadId);
  if (query.page) params.set("page", String(query.page));
  if (query.perPage) params.set("per_page", String(query.perPage));

  return params;
}

export class NexusInboxApiClient {
  private readonly baseUrl: string;
  private readonly bearerToken: string;

  constructor(options: ApiClientOptions = {}) {
    this.baseUrl = options.baseUrl ?? DEFAULT_BASE_URL;
    this.bearerToken = options.bearerToken ?? "";
  }

  private resolveBearerToken(): string {
    return this.bearerToken;
  }

  private async request<T>(
    path: string,
    init?: RequestInit,
    options?: { auth?: boolean },
  ): Promise<T> {
    const headers = new Headers(init?.headers);
    headers.set("Content-Type", "application/json");
    if (options?.auth !== false) {
      const token = this.resolveBearerToken().trim();
      if (token) {
        headers.set("Authorization", "Bearer " + token);
      }
    }

    const response = await fetch(this.baseUrl + path, {
      ...init,
      headers,
      cache: "no-store",
      credentials: "include",
    });

    if (!response.ok) {
      let message = response.statusText;
      try {
        const payload = (await response.json()) as { message?: string };
        message = payload.message ?? message;
      } catch {
        // no-op
      }
      throw new ApiError(message || "request failed", response.status);
    }

    return (await response.json()) as T;
  }

  async listMessages(query: MessageListQuery): Promise<MessageListResponse> {
    const params = toSearchParams(query);
    return this.request<MessageListResponse>("/messages?" + params.toString());
  }

  async listAgents(): Promise<AgentsResponse> {
    return this.request<AgentsResponse>("/agents");
  }

  async createAgent(payload: CreateAgentRequest): Promise<CreateAgentResponse> {
    return this.request<CreateAgentResponse>("/agents", {
      method: "POST",
      body: JSON.stringify(payload),
    });
  }

  async updateAgent(id: string, payload: UpdateAgentRequest): Promise<UpdateAgentResponse> {
    return this.request<UpdateAgentResponse>("/agents/" + encodeURIComponent(id), {
      method: "PATCH",
      body: JSON.stringify(payload),
    });
  }

  async listAgentCredentials(): Promise<AgentCredentialsResponse> {
    return this.request<AgentCredentialsResponse>("/agent-credentials");
  }

  async createAgentCredential(payload: CreateAgentCredentialRequest): Promise<AgentCredential> {
    return this.request<AgentCredential>("/agent-credentials", {
      method: "POST",
      body: JSON.stringify(payload),
    });
  }

  async revokeAgentCredential(id: string): Promise<void> {
    const headers = new Headers({ "Content-Type": "application/json" });
    const token = this.bearerToken.trim();
    if (token) headers.set("Authorization", "Bearer " + token);
    const response = await fetch(this.baseUrl + "/agent-credentials/" + encodeURIComponent(id), {
      method: "DELETE",
      headers,
      cache: "no-store",
      credentials: "include",
    });
    if (!response.ok) {
      throw new ApiError(response.statusText || "revoke credential failed", response.status);
    }
  }

  /**
   * Physically delete a revoked credential row. Only succeeds if the
   * row is `status='revoked'` and was revoked at least the server-side
   * grace period ago (default 7 days). See docs §non-interactive-agent
   * or `purge_agent_credential` in services/api for the contract.
   */
  async purgeAgentCredential(id: string): Promise<void> {
    const headers = new Headers({ "Content-Type": "application/json" });
    const token = this.bearerToken.trim();
    if (token) headers.set("Authorization", "Bearer " + token);
    const response = await fetch(
      this.baseUrl + "/agent-credentials/" + encodeURIComponent(id) + "/purge",
      {
        method: "POST",
        headers,
        cache: "no-store",
        credentials: "include",
      },
    );
    if (!response.ok) {
      // Surface the server's structured error (e.g. purge_grace_period)
      // so the UI can distinguish "try again later" from other failures.
      let message = response.statusText || "purge credential failed";
      try {
        const body = (await response.json()) as { message?: string; error?: string };
        if (body?.message) message = body.message;
        else if (body?.error) message = body.error;
      } catch {}
      throw new ApiError(message, response.status);
    }
  }

  async refreshAgentToken(refreshToken: string): Promise<AgentAuthTokenResponse> {
    return this.request<AgentAuthTokenResponse>(
      "/agent-auth/refresh",
      {
        method: "POST",
        body: JSON.stringify({ refresh_token: refreshToken } satisfies AgentAuthRefreshRequest),
      },
      { auth: false },
    );
  }

  async listAuditLog(query?: AuditLogQuery): Promise<AuditLogResponse> {
    const params = new URLSearchParams();
    if (query?.credential_id) params.set("credential_id", query.credential_id);
    if (query?.aid) params.set("aid", query.aid);
    if (query?.event) params.set("event", query.event);
    if (query?.event_prefix) params.set("event_prefix", query.event_prefix);
    if (query?.limit) params.set("limit", String(query.limit));
    if (query?.offset) params.set("offset", String(query.offset));
    const qs = params.toString();
    return this.request<AuditLogResponse>("/agent-audit-log" + (qs ? "?" + qs : ""));
  }

  async emergencyShutdown(agentId: string): Promise<EmergencyShutdownResponse> {
    return this.request<EmergencyShutdownResponse>(
      "/agents/" + encodeURIComponent(agentId) + "/emergency-shutdown",
      { method: "POST", body: JSON.stringify({}) },
    );
  }

  async getAutoReplyPolicy(agentId: string): Promise<AutoReplyPolicyResponse> {
    return this.request<AutoReplyPolicyResponse>(
      "/agents/" + encodeURIComponent(agentId) + "/auto-reply-policy",
    );
  }

  async putAutoReplyPolicy(
    agentId: string,
    payload: PutAutoReplyPolicyRequest,
  ): Promise<AutoReplyPolicyResponse> {
    return this.request<AutoReplyPolicyResponse>(
      "/agents/" + encodeURIComponent(agentId) + "/auto-reply-policy",
      { method: "PUT", body: JSON.stringify(payload) },
    );
  }

  async deleteAutoReplyPolicy(agentId: string): Promise<void> {
    const headers = new Headers({ "Content-Type": "application/json" });
    const token = this.bearerToken.trim();
    if (token) headers.set("Authorization", "Bearer " + token);
    const response = await fetch(
      this.baseUrl + "/agents/" + encodeURIComponent(agentId) + "/auto-reply-policy",
      {
        method: "DELETE",
        headers,
        cache: "no-store",
        credentials: "include",
      },
    );
    if (!response.ok) {
      throw new ApiError(
        response.statusText || "delete auto-reply policy failed",
        response.status,
      );
    }
  }

  async deleteAgent(id: string): Promise<void> {
    const headers = new Headers({ "Content-Type": "application/json" });
    const token = this.bearerToken.trim();
    if (token) headers.set("Authorization", "Bearer " + token);
    const response = await fetch(this.baseUrl + "/agents/" + encodeURIComponent(id), {
      method: "DELETE",
      headers,
      cache: "no-store",
      credentials: "include",
    });
    if (!response.ok) {
      throw new ApiError(response.statusText || "delete agent failed", response.status);
    }
  }

  async getMessageContent(id: string): Promise<MessageContentResponse> {
    return this.request<MessageContentResponse>(
      "/messages/" + encodeURIComponent(id) + "/content",
    );
  }

  async updateMessageStatus(id: string, status: Extract<MessageStatus, "read" | "archived">) {
    return this.request<{ id: string; status: MessageStatus }>("/messages/" + encodeURIComponent(id), {
      method: "PATCH",
      body: JSON.stringify({ status }),
    });
  }

  async updateMessageFlags(
    id: string,
    flags: { folder?: string; starred?: boolean },
  ) {
    return this.request<{ id: string; folder: string; starred: boolean }>(
      "/messages/" + encodeURIComponent(id) + "/flags",
      {
        method: "PATCH",
        body: JSON.stringify(flags),
      },
    );
  }

  /**
   * Permanently delete a message. The server handler removes this
   * owner's `message_index` row, then GC's the underlying encrypted
   * blob iff no peer row still references the same `storage_ref`
   * (cross-user sender/recipient duplication is handled correctly).
   * Returns 204 No Content on success — we don't go through
   * {@link request} because that helper unconditionally calls
   * `response.json()` which throws on an empty body.
   */
  async deleteMessage(id: string): Promise<void> {
    const headers = new Headers();
    const token = this.bearerToken.trim();
    if (token) headers.set("Authorization", "Bearer " + token);
    const response = await fetch(this.baseUrl + "/messages/" + encodeURIComponent(id), {
      method: "DELETE",
      headers,
      cache: "no-store",
      credentials: "include",
    });
    if (!response.ok) {
      let message = response.statusText;
      try {
        const payload = (await response.json()) as { message?: string };
        message = payload.message ?? message;
      } catch {
        // body may be empty on some error paths; fall back to status text
      }
      throw new ApiError(message || "delete failed", response.status);
    }
  }

  /**
   * Phase 4.4c executor idempotency flip. Called by the browser auto-
   * reply executor after it has dispatched the outgoing reply via
   * {@link seedMessage}. See docs/25c §5.2.
   */
  async markAutoReplySent(
    id: string,
    params: { replyMessageId?: string } = {},
  ): Promise<MarkAutoReplySentResponse> {
    const body: MarkAutoReplySentRequest = {};
    if (params.replyMessageId) body.reply_message_id = params.replyMessageId;
    return this.request<MarkAutoReplySentResponse>(
      "/messages/" + encodeURIComponent(id) + "/auto-reply-sent",
      {
        method: "PATCH",
        body: JSON.stringify(body),
      },
    );
  }

  async seedMessage(params: {
    senderDid: string;
    recipientDid: string;
    subjectEncrypted: string;
    encryptedContent: string;
    encryptedKey: string;
    nonce: string;
    signature: string;
    threadId?: string | null;
    attachments?: OutboundAttachmentRef[];
    /**
     * MIME for the encrypted body. Defaults to "text/plain" to
     * preserve the pre-A2A behaviour for every existing caller.
     * A2A (docs/24) callers set this to
     * "application/vnd.nexusinbox.a2a+json; v=1" so the recipient
     * knows to parse the decrypted body as a protocol envelope.
     */
    contentType?: string;
    /**
     * Phase 4.4c executor marker — when the browser auto-reply
     * executor sends a message it tags the envelope so the
     * recipient-side server evaluator skips it and no second auto-
     * reply is triggered. Recommended value: "client_protocol_v1"
     * (docs/25c §3.1).
     */
    autoReplyOrigin?: string;
  }) {
    const attachments = params.attachments ?? [];
    const metadata: Record<string, unknown> = {
      subject_encrypted: params.subjectEncrypted,
      content_type: params.contentType ?? "text/plain",
      has_attachments: attachments.length > 0,
    };
    if (params.threadId) {
      metadata.thread_id = params.threadId;
    }
    if (params.autoReplyOrigin) {
      metadata.auto_reply_origin = params.autoReplyOrigin;
    }
    const body: Record<string, unknown> = {
      sender_did: params.senderDid,
      recipient_did: params.recipientDid,
      envelope: {
        encrypted_content: params.encryptedContent,
        encrypted_key: params.encryptedKey,
        nonce: params.nonce,
        signature: params.signature,
        metadata,
      },
    };
    if (attachments.length > 0) {
      body.attachment_ids = attachments.map((a) => a.attachment_id);
      body.attachments = attachments;
    }
    return this.request<{ message_id: string; status: string }>("/messages", {
      method: "POST",
      body: JSON.stringify(body),
    });
  }

  // --- Attachments (docs/17_attachment_upload_r2_spec.md) ----------------

  async createAttachmentIntent(
    request: CreateAttachmentIntentRequest,
  ): Promise<CreateAttachmentIntentResponse> {
    return this.request<CreateAttachmentIntentResponse>("/attachments/intents", {
      method: "POST",
      body: JSON.stringify(request),
    });
  }

  async completeAttachment(
    attachmentId: string,
    ciphertextSizeBytes: number,
  ): Promise<CompleteAttachmentResponse> {
    return this.request<CompleteAttachmentResponse>(
      `/attachments/${encodeURIComponent(attachmentId)}/complete`,
      {
        method: "POST",
        body: JSON.stringify({ ciphertext_size_bytes: ciphertextSizeBytes }),
      },
    );
  }

  async deleteAttachment(attachmentId: string): Promise<void> {
    await this.request<void>(`/attachments/${encodeURIComponent(attachmentId)}`, {
      method: "DELETE",
    });
  }

  async listMessageAttachments(
    messageId: string,
  ): Promise<ListMessageAttachmentsResponse> {
    return this.request<ListMessageAttachmentsResponse>(
      `/messages/${encodeURIComponent(messageId)}/attachments`,
    );
  }

  async getAttachmentDownloadUrl(
    messageId: string,
    attachmentId: string,
  ): Promise<AttachmentDownloadUrlResponse> {
    return this.request<AttachmentDownloadUrlResponse>(
      `/messages/${encodeURIComponent(messageId)}/attachments/${encodeURIComponent(attachmentId)}/download`,
      { method: "POST", body: "{}" },
    );
  }

  async listBlocks(): Promise<BlocksResponse> {
    return this.request<BlocksResponse>("/blocks");
  }

  async createBlock(payload: CreateBlockRequest): Promise<CreateBlockResponse> {
    return this.request<CreateBlockResponse>("/blocks", {
      method: "POST",
      body: JSON.stringify(payload),
    });
  }

  /**
   * Register a block against the sender of a specific received
   * message. Server resolves sender_did → world_id_hash internally
   * so the UI never has to surface / collect the raw hash.
   */
  async blockFromMessage(
    messageId: string,
    payload: BlockFromMessageRequest,
  ): Promise<BlockFromMessageResponse> {
    return this.request<BlockFromMessageResponse>(
      "/blocks/from-message/" + encodeURIComponent(messageId),
      {
        method: "POST",
        body: JSON.stringify(payload),
      },
    );
  }

  async deleteBlock(id: string): Promise<void> {
    const headers = new Headers({ "Content-Type": "application/json" });
    const token = this.bearerToken.trim();
    if (token) headers.set("Authorization", "Bearer " + token);
    const response = await fetch(this.baseUrl + "/blocks/" + encodeURIComponent(id), {
      method: "DELETE",
      headers,
      cache: "no-store",
      credentials: "include",
    });
    if (!response.ok) {
      throw new ApiError(response.statusText || "delete block failed", response.status);
    }
  }

  async listContacts(): Promise<ContactsResponse> {
    return this.request<ContactsResponse>("/contacts");
  }

  async resolveRecipient(identifier: string): Promise<RecipientResolutionResponse> {
    const params = new URLSearchParams({ identifier });
    return this.request<RecipientResolutionResponse>("/recipients/resolve?" + params.toString());
  }

  async createContact(payload: CreateContactRequest): Promise<CreateContactResponse> {
    return this.request<CreateContactResponse>("/contacts", {
      method: "POST",
      body: JSON.stringify(payload),
    });
  }

  async updateContact(id: string, payload: UpdateContactRequest): Promise<ContactEntry> {
    return this.request<ContactEntry>("/contacts/" + encodeURIComponent(id), {
      method: "PATCH",
      body: JSON.stringify(payload),
    });
  }

  async deleteContact(id: string): Promise<void> {
    const headers = new Headers({ "Content-Type": "application/json" });
    const token = this.bearerToken.trim();
    if (token) headers.set("Authorization", "Bearer " + token);
    const response = await fetch(this.baseUrl + "/contacts/" + encodeURIComponent(id), {
      method: "DELETE",
      headers,
      cache: "no-store",
      credentials: "include",
    });
    if (!response.ok) {
      throw new ApiError(response.statusText || "delete contact failed", response.status);
    }
  }

  async approveMessage(id: string): Promise<{ id: string; status: MessageStatus }> {
    return this.updateMessageStatus(id, "read");
  }

  async rejectMessage(id: string): Promise<{ id: string; status: MessageStatus }> {
    return this.updateMessageStatus(id, "archived");
  }

  async verifyAuth(payload: AuthVerifyRequest): Promise<AuthVerifyResponse> {
    return this.request<AuthVerifyResponse>(
      "/auth/verify",
      {
        method: "POST",
        body: JSON.stringify(payload),
      },
      { auth: false },
    );
  }

  async getStatus(): Promise<StatusResponse> {
    return this.request<StatusResponse>("/status", { method: "GET" }, { auth: false });
  }

  async getAuthSession(): Promise<AuthSessionResponse> {
    // Do not throw on 401/unauthenticated: callers rely on the
    // `authenticated` flag to decide how to react. Throwing would
    // leave TanStack Query in an error state with undefined data,
    // which races against guards that drive /login redirects.
    const response = await fetch(this.baseUrl + "/auth/session", {
      method: "GET",
      headers: { "Content-Type": "application/json" },
      cache: "no-store",
      credentials: "include",
    });

    if (response.status === 401 || response.status === 403) {
      return { authenticated: false } as AuthSessionResponse;
    }

    if (!response.ok) {
      throw new ApiError(response.statusText || "auth session failed", response.status);
    }

    return (await response.json()) as AuthSessionResponse;
  }

  async updateAuthProfile(payload: UpdateProfileRequest): Promise<AuthSessionResponse> {
    return this.request<AuthSessionResponse>(
      "/auth/session",
      {
        method: "PATCH",
        body: JSON.stringify(payload),
      },
      { auth: false },
    );
  }

  async logoutAuth(): Promise<AuthLogoutResponse> {
    return this.request<AuthLogoutResponse>(
      "/auth/logout",
      {
        method: "POST",
        body: JSON.stringify({}),
      },
      { auth: false },
    );
  }
}

export const defaultApiClient = new NexusInboxApiClient();

// Produce a friendly display for a participant. Falls back to a
// short prefix of the DID so the inbox is never dominated by raw
// base58 strings. Prefer the server-computed label when available.
export function formatParticipant(label: string | null | undefined, did: string): string {
  const trimmed = label?.trim();
  if (trimmed) return trimmed;
  if (!did) return "(不明な相手)";
  if (did.length <= 18) return did;
  return did.slice(0, 12) + "…" + did.slice(-4);
}

export function mapPriorityLabel(priority: MessagePriority): string {
  switch (priority) {
    case "high":
      return "優先度 高";
    case "normal":
      return "優先度 標準";
    case "low":
      return "優先度 低";
    case "background":
      return "要確認";
    default:
      return "優先度 標準";
  }
}
