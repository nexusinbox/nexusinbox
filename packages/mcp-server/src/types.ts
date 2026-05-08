export type ToolPhase = "phase1a" | "phase1b" | "phase2";

export type ToolRisk = "low" | "medium" | "high";

export type ToolDefinition = {
  name: string;
  description: string;
  phase: ToolPhase;
  risk: ToolRisk;
  requiresConfirmation?: boolean;
  inputSchema: Record<string, unknown>;
};

export type AgentSummary = {
  aid: string;
  did: string;
  label?: string | null;
};

export type InboxMessageSummary = {
  message_id: string;
  sender_aid?: string | null;
  sender_did: string;
  subject: string;
  created_at: string;
  status: string;
  folder: string;
};

export type MessageAttachmentSummary = {
  attachment_id: string;
  filename: string;
  mime: string;
  plaintext_size_bytes: number;
};

export type ReadMessageResult = {
  message_id: string;
  sender?: { aid?: string | null; did: string };
  recipient?: { aid?: string | null; did: string };
  subject: string;
  body: string;
  attachments: MessageAttachmentSummary[];
};

export type RecipientResolutionResult = {
  aid: string;
  did: string;
  label?: string | null;
  encryption_public_key: string;
};

export type DraftEnvelopeResult = {
  mode: "draft";
  sender_aid: string;
  recipient_aid?: string;
  recipient_did: string;
  subject: string;
  body_markdown: string;
  thread_id?: string | null;
  /**
   * SHA-256 hex digest of the exact body string that would be sent if
   * the caller re-submits with `mode: "send"`. Echoed to the audit log
   * so draft → send transitions are linkable without persisting plain-
   * text anywhere.
   */
  draft_body_hash: string;
};

export type SentMessageResult = {
  mode: "send";
  message_id: string;
  status: string;
  thread_id?: string | null;
  /** Matches the hash the caller saw in the preceding draft response. */
  draft_body_hash: string;
};

export type SendMode = "draft" | "send";

/** Common options for every write tool. */
export type WriteOptions = {
  /**
   * Required when `mode === "send"`. The Phase 1B policy refuses
   * un-confirmed sends outright; the LLM host must either surface a
   * confirmation prompt to the human and echo `true`, or leave it
   * unset and send the draft first.
   */
  confirmed_by_user?: boolean;
  /**
   * Free-form short string identifying the LLM provider + model that
   * drove the call (e.g. `"claude-sonnet-4.5"`, `"cursor-inline"`).
   * Logged verbatim to the audit stream; never used for authz.
   */
  provider_hint?: string;
};

export interface NexusInboxMcpRuntime {
  listMyAgents(): Promise<{ agents: AgentSummary[] }>;
  listInbox(input: {
    agent_aid: string;
    folder?: string;
    status?: string;
    page?: number;
    per_page?: number;
  }): Promise<{ messages: InboxMessageSummary[]; total: number; page: number; per_page: number }>;
  readMessage(input: { message_id: string }): Promise<ReadMessageResult>;
  resolveRecipient(input: { identifier: string }): Promise<RecipientResolutionResult>;
  sendTextMessage(
    input: {
      from_agent: string;
      to: string;
      subject: string;
      body_markdown: string;
      mode?: SendMode;
    } & WriteOptions,
  ): Promise<DraftEnvelopeResult | SentMessageResult>;
  replyToMessage(
    input: {
      incoming_message_id: string;
      body_markdown: string;
      /** Optional override. Defaults to "Re: " + decrypted incoming subject. */
      subject?: string;
      mode?: SendMode;
    } & WriteOptions,
  ): Promise<DraftEnvelopeResult | SentMessageResult>;
}
