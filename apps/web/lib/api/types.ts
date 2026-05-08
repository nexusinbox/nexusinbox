export type MessagePriority = "high" | "normal" | "low" | "background";
export type MessageStatus = "unread" | "read" | "archived";
export type MessageFolder =
  | "inbox"
  | "sent"
  | "drafts"
  | "archive"
  | "spam"
  | "trash"
  | "pending_approval";
// Virtual folders are not real buckets — the server resolves them by
// combining folder+starred+exclusions. Kept as a separate type so the
// call-site knows they can only appear in queries, never as a stored
// value on MessageIndexEntry.folder.
export type MessageFolderQuery = MessageFolder | "starred" | "all";

// Raw IDKit result forwarded directly to the backend.
// The backend adds action and forwards to World ID v4 verify API.
export type AuthVerifyRequest = {
  // Raw IDKit result (protocol_version 3.0 or 4.0)
  idkit_result: Record<string, unknown>;
  // Action name for verification
  action: string;
};

export type AuthVerifyResponse = {
  user: {
    id: string;
    display_name: string | null;
    verification_level: string;
    created_at: string;
  };
};

export type AuthLogoutResponse = {
  success: boolean;
};

export type AuthSessionUser = {
  id: string;
  display_name: string | null;
  verification_level: string;
  created_at: string;
};

export type AuthSessionResponse = {
  authenticated: boolean;
  user?: AuthSessionUser;
};

export type UpdateProfileRequest = {
  display_name: string | null;
};

export type StatusResponse = {
  service: string;
  version: string;
  storage_backend: string;
  database_configured: boolean;
  database_connected: boolean;
  auto_purge_enabled: boolean;
  websocket_enabled: boolean;
  world_id_verify_enabled: boolean;
};

export type Agent = {
  id: string;
  aid: string;
  did: string;
  label: string;
  public_key?: string;
  encryption_key?: string;
  is_active: boolean;
  auto_reply: boolean;
  unread_count: number;
  created_at: string;
};

export type AgentsResponse = {
  agents: Agent[];
};

export type CreateAgentRequest = {
  label: string;
  public_key: string;
  encryption_key: string;
};

export type CreateAgentResponse = {
  id: string;
  aid: string;
  did: string;
};

// Agent Credentials (non-interactive access)

export type AgentCredential = {
  credential_id: string;
  aid: string;
  label: string;
  status: "pending" | "active" | "revoked" | "compromised";
  allowed_scopes: string[];
  enrollment_secret?: string | null;
  enrollment_expires_at?: string | null;
  created_at: string;
  activated_at?: string | null;
  last_used_at?: string | null;
  /**
   * ISO timestamp; populated when `status === 'revoked'`. Used to compute
   * the client-side purge grace countdown.
   */
  revoked_at?: string | null;
  /**
   * Where the private-key material for this credential lives. Comes
   * straight from the API (migration 0014). The UI renders a Mode
   * badge from this value; pre-migration credentials return
   * `"unknown"` and the settings page treats them as Standard.
   * See docs/21_message_visibility_ux_for_mcp_modes.md §7.
   */
  key_holder?: "web_keystore" | "signer_daemon" | "unknown";
};

export type AgentCredentialsResponse = {
  credentials: AgentCredential[];
};

export type CreateAgentCredentialRequest = {
  agent_id: string;
  label: string;
  scopes?: string[];
};

export type RecipientResolutionResponse = {
  input: string;
  aid: string;
  did: string;
  label: string | null;
  signing_public_key: string;
  encryption_public_key: string;
  /**
   * Aggregate mode over the recipient agent's active credentials.
   * Optional because older API builds don't return it — absence
   * should be treated as `"unknown"` in the UI (i.e. show no hint).
   * See docs/21_message_visibility_ux_for_mcp_modes.md §4.4.
   */
  key_holder?: "web_keystore" | "signer_daemon" | "unknown";
};

// Agent Auth Token (non-interactive access)

export type AgentAuthTokenResponse = {
  access_token: string;
  refresh_token: string;
  token_type: "Bearer" | "DPoP";
  expires_in: number;
  scope: string;
};

export type AgentAuthRefreshRequest = {
  refresh_token: string;
};

export type UpdateAgentRequest = {
  label?: string;
  auto_reply?: boolean;
};

export type UpdateAgentResponse = {
  id: string;
  label: string;
  auto_reply: boolean;
};

export type AutoReplyDecision =
  | "queue_for_human"
  | "auto_accept"
  | "auto_decline"
  | "auto_accept_if_free"
  | "delegate_to_llm";

export type MessageIndexEntry = {
  id: string;
  sender_did: string;
  sender_label: string | null;
  recipient_did: string;
  recipient_label: string | null;
  thread_id: string | null;
  subject_encrypted: string;
  status: MessageStatus;
  priority: MessagePriority;
  ai_category: string | null;
  created_at: string;
  trust_score: number;
  folder: MessageFolder;
  starred: boolean;
  // Phase 4.4b: cached auto-reply evaluator output. Absent when the
  // evaluator has not run for this row (pre-4.4b, or server gate off).
  // See docs/25b for decision/reason codes.
  auto_reply_decision?: AutoReplyDecision;
  auto_reply_reason?: string;
  // Phase 4.4c: set by the executor after it has dispatched the
  // auto-reply for this recipient-side row. See docs/25c §3.2.
  auto_reply_sent_at?: string;
};

export type MarkAutoReplySentRequest = {
  reply_message_id?: string;
};

export type MarkAutoReplySentResponse = {
  id: string;
  auto_reply_sent_at: string;
};

export type UpdateMessageFlagsRequest = {
  folder?: MessageFolder;
  starred?: boolean;
};

export type UpdateMessageFlagsResponse = {
  id: string;
  folder: MessageFolder;
  starred: boolean;
};

export type MessageListResponse = {
  messages: MessageIndexEntry[];
  total: number;
  page: number;
  per_page: number;
};

export type MessageContentResponse = {
  encrypted_content: string;
  encrypted_key: string;
  nonce: string;
  // Added so the compose page can prefill a reply's recipient + subject
  // and so replies can continue the existing thread. Optional for
  // forward-compat with older API builds.
  sender_did?: string;
  recipient_did?: string;
  subject_encrypted?: string;
  thread_id?: string | null;
  // MIME type of the decrypted body. Used by the inbox UI to decide
  // whether to parse the body as an A2A protocol payload (docs/24)
  // or render it as plain text/markdown. Optional for forward-compat
  // with older API builds and legacy stored messages.
  content_type?: string | null;
};

// --- Attachment upload types (docs/17_attachment_upload_r2_spec.md) -------

export type CreateAttachmentIntentRequest = {
  sender_did?: string;
  draft_id?: string;
  ciphertext_size_bytes: number;
};

export type CreateAttachmentIntentResponse = {
  attachment_id: string;
  upload_url: string;
  upload_method: string;
  upload_expires_at: string;
  required_headers: Record<string, string>;
  max_ciphertext_size_bytes: number;
};

export type CompleteAttachmentResponse = {
  attachment_id: string;
  status: string;
};

export type MessageAttachmentSummary = {
  attachment_id: string;
  metadata_encrypted: string;
  metadata_nonce: string;
  ciphertext_size_bytes: number;
};

export type ListMessageAttachmentsResponse = {
  attachments: MessageAttachmentSummary[];
};

export type AttachmentDownloadUrlResponse = {
  download_url: string;
  expires_at: string;
};

/**
 * Plaintext shape of the per-attachment metadata blob that gets encrypted
 * with the message's content key before being sent as `metadata_encrypted`.
 * The server never sees this — it only sees the ciphertext.
 */
export type AttachmentMetadataPlain = {
  filename: string;
  mime: string;
  plaintext_size_bytes: number;
  cipher_algorithm: "aes-gcm-256";
  cipher_nonce: string;
  attachment_key_wraps: Array<{
    recipient_did: string;
    wrapped_key: string;
  }>;
  sha256_plaintext: string;
};

/**
 * Payload shape the compose page passes to `seedMessage` for each attachment.
 * `attachment_id` comes from the intents endpoint; `metadata_encrypted` is
 * the client-encrypted AttachmentMetadataPlain.
 */
export type OutboundAttachmentRef = {
  attachment_id: string;
  metadata_encrypted: string;
  metadata_nonce: string;
};

export type MessageListQuery = {
  agentDid: string;
  status?: "unread" | "read" | "all";
  priority?: MessagePriority;
  folder?: MessageFolderQuery;
  threadId?: string;
  page?: number;
  perPage?: number;
};

export type BlockLevel = "l1_did" | "l2_identity" | "l3_stealth";

export type BlockEntry = {
  id: string;
  level: BlockLevel;
  target_did: string | null;
  target_world_id: string | null;
  created_at: string;
};

export type BlocksResponse = {
  blocks: BlockEntry[];
};

export type CreateBlockRequest = {
  level: BlockLevel;
  target_did?: string;
  target_world_id?: string;
};

export type CreateBlockResponse = {
  id: string;
};

/**
 * Body for `POST /blocks/from-message/:message_id`. The server
 * derives the target identifier (sender_did for L1, world_id_hash
 * for L2/L3) from the message's owner-scoped row so the UI never
 * needs to handle a World ID nullifier hash by hand.
 */
export type BlockFromMessageRequest = {
  level: BlockLevel;
};

/**
 * Response shape for the "Block sender" flow. Includes the resolved
 * target so the client can surface "Blocked did:key:…" / "Blocked
 * this sender's World ID" in the confirmation toast without a
 * second round-trip.
 */
export type BlockFromMessageResponse = {
  id: string;
  level: BlockLevel;
  target_did: string | null;
  target_world_id: string | null;
};

export type ContactEntry = {
  id: string;
  did: string;
  person_name: string;
  agent_label: string | null;
  note: string | null;
  created_at: string;
  updated_at: string;
};

export type ContactsResponse = {
  contacts: ContactEntry[];
};

export type CreateContactRequest = {
  did: string;
  person_name: string;
  agent_label?: string | null;
  note?: string | null;
};

export type CreateContactResponse = {
  id: string;
};

export type UpdateContactRequest = {
  person_name?: string;
  agent_label?: string | null;
  note?: string | null;
};

// Audit log

export type AuditLogEntry = {
  id: string;
  credential_id: string | null;
  aid: string | null;
  event: string;
  detail: Record<string, unknown>;
  created_at: string;
};

export type AuditLogResponse = {
  events: AuditLogEntry[];
  total: number;
};

export type AuditLogQuery = {
  credential_id?: string;
  /**
   * Filter by agent identifier (`aid:ai:...`). Used by per-agent
   * visibility panels (e.g. auto-reply decision history) so the
   * client doesn't need to over-fetch and filter by aid in JS.
   * Server caps the value length at 128 chars and only does an
   * equality match — no wildcards.
   */
  aid?: string;
  event?: string;
  /**
   * Prefix match on the `event` column — useful for grouping
   * `bridged_*` Phase 3c.3 events into a single dashboard view.
   * Server silently ignores non-alphanumeric/underscore input to
   * defang LIKE wildcard injection.
   */
  event_prefix?: string;
  limit?: number;
  offset?: number;
};

export type EmergencyShutdownResponse = {
  agent_id: string;
  aid: string;
  credentials_revoked: number;
  tokens_revoked: number;
};

// --- Auto-reply policy (Phase 4.4a, docs/25) ------------------------------

export type AutoReplyAction =
  | "queue_for_human"
  | "auto_accept"
  | "auto_decline"
  | "auto_accept_if_free" // Phase 4.4d (Calendar), UI may disable until landing
  | "delegate_to_llm";    // Phase 4.4e (LLM), UI may disable until landing

export type AutoReplyPriorityValue = "high" | "normal" | "low" | "background";

export type AutoReplyConditions = {
  min_trust_score?: number;      // 0.0 - 1.0
  require_contact?: boolean;
  priority_at_most?: AutoReplyPriorityValue;
  sender_in_allowlist?: string[];
};

export type AutoReplyProtocolAction = {
  action: AutoReplyAction;
  conditions?: AutoReplyConditions;
  note_template?: string;
};

export type AutoReplyPolicy = {
  v: 1;
  default_action: AutoReplyAction;
  protocols?: {
    schedule_negotiation?: {
      propose?: AutoReplyProtocolAction;
    };
    task_delegation?: {
      delegate?: AutoReplyProtocolAction;
    };
  };
};

export type AutoReplyPolicyResponse = {
  agent_id: string;
  schema_version: 1;
  /**
   * 0 when no row exists yet. Clients should echo back in subsequent
   * PUT requests (via `If-Match` header or body `revision` field) so
   * the server can detect concurrent edits.
   */
  revision: number;
  /** Empty object when no row exists yet. */
  policy: AutoReplyPolicy | Record<string, never>;
  updated_at: string | null;
};

export type PutAutoReplyPolicyRequest = {
  policy: AutoReplyPolicy;
  /**
   * Optional revision. The server prefers the `If-Match` header but
   * accepts this body field as a fallback for proxies / CDNs that
   * strip conditional-request headers.
   */
  revision?: number;
};
