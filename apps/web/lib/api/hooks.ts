"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { clearAllBridgeTokens } from "../bridge/token-store";
import { disconnectLLM } from "../llm/llmAuth";
import { defaultApiClient } from "./client";
import {
  AuditLogQuery,
  AuthVerifyRequest,
  BlockFromMessageRequest,
  CreateAgentCredentialRequest,
  CreateAgentRequest,
  CreateBlockRequest,
  CreateContactRequest,
  MessageListQuery,
  OutboundAttachmentRef,
  PutAutoReplyPolicyRequest,
  UpdateAgentRequest,
  UpdateContactRequest,
  UpdateProfileRequest,
} from "./types";

export const queryKeys = {
  agentCredentials: () => ["agent-credentials"] as const,
  agents: () => ["agents"] as const,
  messages: (query: MessageListQuery) => ["messages", query] as const,
  messageContent: (id: string | null) => ["message-content", id] as const,
  messageAttachments: (id: string | null) => ["message-attachments", id] as const,
  blocks: () => ["blocks"] as const,
  contacts: () => ["contacts"] as const,
  authSession: () => ["auth", "session"] as const,
  status: () => ["status"] as const,
  auditLog: (query?: AuditLogQuery) => ["audit-log", query] as const,
  autoReplyPolicy: (agentId: string | null) =>
    ["auto-reply-policy", agentId] as const,
};

export function useStatusQuery() {
  return useQuery({
    queryKey: queryKeys.status(),
    queryFn: () => defaultApiClient.getStatus(),
    staleTime: 30_000,
    retry: 1,
  });
}

export function useAuthSessionQuery() {
  return useQuery({
    queryKey: queryKeys.authSession(),
    queryFn: () => defaultApiClient.getAuthSession(),
    staleTime: 15_000,
    retry: 0,
  });
}

export function useUpdateProfileMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: UpdateProfileRequest) => defaultApiClient.updateAuthProfile(payload),
    onSuccess: (data) => {
      queryClient.setQueryData(queryKeys.authSession(), data);
    },
  });
}

export function useBlocksQuery() {
  return useQuery({
    queryKey: queryKeys.blocks(),
    queryFn: () => defaultApiClient.listBlocks(),
    staleTime: 30_000,
    retry: 1,
  });
}

export function useCreateBlockMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: CreateBlockRequest) => defaultApiClient.createBlock(payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.blocks() });
    },
  });
}

/**
 * Register a block against the sender of a specific received message.
 * The UI passes `message_id` + policy level; server resolves the
 * target identifier (sender_did for L1, world_id_hash for L2/L3).
 * Refreshes the blocks list on success so the /settings/blocks
 * panel reflects the new row without a manual refetch.
 */
export function useBlockFromMessageMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({
      messageId,
      payload,
    }: {
      messageId: string;
      payload: BlockFromMessageRequest;
    }) => defaultApiClient.blockFromMessage(messageId, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.blocks() });
    },
  });
}

export function useDeleteBlockMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => defaultApiClient.deleteBlock(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.blocks() });
    },
  });
}

export function useContactsQuery() {
  return useQuery({
    queryKey: queryKeys.contacts(),
    queryFn: () => defaultApiClient.listContacts(),
    staleTime: 30_000,
    retry: 1,
  });
}

export function useCreateContactMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: CreateContactRequest) => defaultApiClient.createContact(payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.contacts() });
    },
  });
}

export function useUpdateContactMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: { id: string; body: UpdateContactRequest }) =>
      defaultApiClient.updateContact(payload.id, payload.body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.contacts() });
    },
  });
}

export function useDeleteContactMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => defaultApiClient.deleteContact(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.contacts() });
    },
  });
}

export function useAgentsQuery() {
  return useQuery({
    queryKey: queryKeys.agents(),
    queryFn: () => defaultApiClient.listAgents(),
    staleTime: 30_000,
    retry: 1,
  });
}

export function useMessagesQuery(query: MessageListQuery) {
  return useQuery({
    queryKey: queryKeys.messages(query),
    queryFn: () => defaultApiClient.listMessages(query),
    staleTime: 30_000,
    retry: 1,
  });
}

export function useCreateAgentMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: CreateAgentRequest) => defaultApiClient.createAgent(payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.agents() });
    },
  });
}

export function useUpdateAgentMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: { id: string; body: UpdateAgentRequest }) =>
      defaultApiClient.updateAgent(payload.id, payload.body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.agents() });
    },
  });
}

export function useAgentCredentialsQuery() {
  return useQuery({
    queryKey: queryKeys.agentCredentials(),
    queryFn: () => defaultApiClient.listAgentCredentials(),
    staleTime: 30_000,
    retry: 1,
  });
}

export function useCreateAgentCredentialMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: CreateAgentCredentialRequest) =>
      defaultApiClient.createAgentCredential(payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.agentCredentials() });
    },
  });
}

export function useRevokeAgentCredentialMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => defaultApiClient.revokeAgentCredential(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.agentCredentials() });
    },
  });
}

export function usePurgeAgentCredentialMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => defaultApiClient.purgeAgentCredential(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.agentCredentials() });
    },
  });
}

export function useDeleteAgentMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => defaultApiClient.deleteAgent(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.agents() });
      queryClient.invalidateQueries({ queryKey: ["messages"] });
    },
  });
}

export function useEmergencyShutdownMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (agentId: string) => defaultApiClient.emergencyShutdown(agentId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.agentCredentials() });
      queryClient.invalidateQueries({ queryKey: queryKeys.agents() });
      queryClient.invalidateQueries({ queryKey: queryKeys.auditLog() });
    },
  });
}

export function useAutoReplyPolicyQuery(agentId: string | null) {
  return useQuery({
    queryKey: queryKeys.autoReplyPolicy(agentId),
    queryFn: () => {
      if (!agentId) {
        throw new Error("agentId is required");
      }
      return defaultApiClient.getAutoReplyPolicy(agentId);
    },
    enabled: Boolean(agentId),
    staleTime: 5_000,
  });
}

export function useUpdateAutoReplyPolicyMutation(agentId: string | null) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: PutAutoReplyPolicyRequest) => {
      if (!agentId) {
        throw new Error("agentId is required");
      }
      return defaultApiClient.putAutoReplyPolicy(agentId, payload);
    },
    onSuccess: (data) => {
      if (agentId) {
        // Write through so the next read doesn't round-trip, but
        // still invalidate in case another tab beat us to it.
        queryClient.setQueryData(queryKeys.autoReplyPolicy(agentId), data);
        queryClient.invalidateQueries({ queryKey: queryKeys.auditLog() });
      }
    },
  });
}

export function useDeleteAutoReplyPolicyMutation(agentId: string | null) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => {
      if (!agentId) {
        throw new Error("agentId is required");
      }
      return defaultApiClient.deleteAutoReplyPolicy(agentId);
    },
    onSuccess: () => {
      if (agentId) {
        queryClient.invalidateQueries({
          queryKey: queryKeys.autoReplyPolicy(agentId),
        });
        queryClient.invalidateQueries({ queryKey: queryKeys.auditLog() });
      }
    },
  });
}

export function useSendMessageMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: {
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
       * MIME of the decrypted body. Set to the A2A MIME
       * (`application/vnd.nexusinbox.a2a+json; v=1`) when sending
       * a protocol message so the recipient's client can dispatch
       * on it. Defaults to `text/plain` in the API client when
       * omitted, preserving pre-A2A behaviour.
       */
      contentType?: string;
    }) => defaultApiClient.seedMessage(payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["messages"] });
    },
  });
}

export function useUpdateMessageStatusMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: { id: string; status: "read" | "archived" }) =>
      defaultApiClient.updateMessageStatus(payload.id, payload.status),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["messages"] });
      queryClient.invalidateQueries({ queryKey: ["message-content"] });
    },
  });
}

export function useUpdateMessageFlagsMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: {
      id: string;
      folder?: string;
      starred?: boolean;
    }) =>
      defaultApiClient.updateMessageFlags(payload.id, {
        folder: payload.folder,
        starred: payload.starred,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["messages"] });
    },
  });
}

export function useDeleteMessageMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => defaultApiClient.deleteMessage(id),
    onSuccess: () => {
      // The deleted row is gone from message_index AND the blob may
      // be GC'd from storage. Invalidate both the list and any
      // per-message content cache that might still hold stale plaintext.
      queryClient.invalidateQueries({ queryKey: ["messages"] });
      queryClient.invalidateQueries({ queryKey: ["message-content"] });
    },
  });
}

export function useAuthVerifyMutation() {
  return useMutation({
    mutationFn: (payload: AuthVerifyRequest) => defaultApiClient.verifyAuth(payload),
  });
}

export function useAuthLogoutMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => defaultApiClient.logoutAuth(),
    onSuccess: async () => {
      await queryClient.clear();
    },
    onSettled: async () => {
      // Session-scoped secrets die with the session, even when the
      // server call failed (the button navigates to /login regardless).
      // Both are re-obtainable: re-pair the bridge, re-enter the LLM
      // key. The E2E private keys in IndexedDB are deliberately left
      // alone — this browser may hold the only copy.
      clearAllBridgeTokens();
      await disconnectLLM();
    },
  });
}

export function useMessageContentQuery(id: string | null) {
  return useQuery({
    queryKey: queryKeys.messageContent(id),
    queryFn: () => {
      if (!id) {
        throw new Error("message id is required");
      }
      return defaultApiClient.getMessageContent(id);
    },
    enabled: Boolean(id),
    staleTime: 30_000,
    retry: 1,
  });
}

export function useMessageAttachmentsQuery(id: string | null) {
  return useQuery({
    queryKey: queryKeys.messageAttachments(id),
    queryFn: () => {
      if (!id) {
        throw new Error("message id is required");
      }
      return defaultApiClient.listMessageAttachments(id);
    },
    enabled: Boolean(id),
    staleTime: 60_000,
    retry: 1,
  });
}

export function useAuditLogQuery(query?: AuditLogQuery) {
  return useQuery({
    queryKey: queryKeys.auditLog(query),
    queryFn: () => defaultApiClient.listAuditLog(query),
    staleTime: 15_000,
    retry: 1,
  });
}
