"use client";

import { useMemo, useState } from "react";
import { AppShell } from "../_components/AppShell";
import { BlockSenderPanel, type BlockStatus } from "../_components/ConversationThread";
import { Avatar } from "../_components/messages/ConversationView";
import { AgentDrafts } from "./AgentDrafts";
import { agentForDid } from "../_components/InboxAgentBar";
import { RefreshIconButton } from "../_components/RefreshIconButton";
import {
  useAgentsQuery,
  useContactsQuery,
  useMessagesQuery,
  useUpdateMessageFlagsMutation,
} from "../../lib/api/hooks";
import {
  formatPartyLabel,
  indexContactsByDid,
  resolveParticipantLabel,
} from "../../lib/api/labels";
import { useTranslation } from "../../lib/i18n";
import { formatListTimestamp } from "../../lib/format/messageTime";

export default function PendingApprovalPage() {
  const { t, locale } = useTranslation();
  const contactsQuery = useContactsQuery();
  const contactsByDid = useMemo(
    () => indexContactsByDid(contactsQuery.data?.contacts),
    [contactsQuery.data],
  );
  const agentsQuery = useAgentsQuery();
  const agents = useMemo(() => agentsQuery.data?.agents ?? [], [agentsQuery.data]);
  const [statusMessage, setStatusMessage] = useState<string>("");
  // The held message whose sender is being blocked (BlockSenderPanel).
  const [blockingId, setBlockingId] = useState<string | null>(null);
  const [blockStatus, setBlockStatus] = useState<BlockStatus | null>(null);

  // Server-side folder filter: only messages the AI spam pipeline or
  // low trust routing put into the pending_approval bucket show up here.
  const messagesQuery = useMessagesQuery({
    agentDid: "all",
    folder: "pending_approval",
    perPage: 100,
  });
  const updateFlags = useUpdateMessageFlagsMutation();

  const pending = useMemo(
    () => messagesQuery.data?.messages ?? [],
    [messagesQuery.data],
  );

  const handleApprove = async (id: string) => {
    setStatusMessage("");
    try {
      await updateFlags.mutateAsync({ id, folder: "inbox" });
      setStatusMessage(t("pending.approved"));
    } catch {
      setStatusMessage(t("pending.approveFailed"));
    }
  };

  const handleReject = async (id: string) => {
    setStatusMessage("");
    try {
      await updateFlags.mutateAsync({ id, folder: "trash" });
      setStatusMessage(t("pending.rejected"));
    } catch {
      setStatusMessage(t("pending.rejectFailed"));
    }
  };

  return (
    <AppShell
      title={t("pending.title")}
      activePath="/pending"
      rightAction={
        <RefreshIconButton
          onClick={() => messagesQuery.refetch()}
          label={t("pending.refresh")}
        />
      }
    >
      <div className="rv">
        <AgentDrafts />

        <section className="rv-section" data-testid="pending-messages">
          <h3 className="rv-title">{t("pending.heading", { count: pending.length })}</h3>
          <p className="rv-why">{t("pending.descSelected")}</p>
          {messagesQuery.isLoading ? (
            <p className="rv-empty">{t("pending.loading")}</p>
          ) : messagesQuery.isError ? (
            <div className="rv-empty" style={{ color: "var(--danger)" }}>
              {t("pending.error")}
              <div className="dm-btns" style={{ justifyContent: "center" }}>
                <button className="dm-btn" type="button" onClick={() => messagesQuery.refetch()}>
                  {t("pending.retry")}
                </button>
              </div>
            </div>
          ) : pending.length === 0 ? (
            <p className="rv-empty">{t("pending.empty")}</p>
          ) : (
            pending.map((message) => {
              const name = formatPartyLabel(
                resolveParticipantLabel(message.sender_did, message.sender_label, contactsByDid),
                t,
              );
              return (
                <div key={message.id} className="rv-row" data-testid="pending-row">
                  <Avatar did={message.sender_did} name={name} />
                  <div className="dm-row-body">
                    <div className="dm-line1">
                      <span className="dm-name">{name}</span>
                      <span className="dm-time">
                        {formatListTimestamp(message.created_at, { locale })}
                      </span>
                    </div>
                    {/* The subject is encrypted for the recipient agent; it can be
                        read in the conversation once accepted. */}
                    <p className="rv-text">{t("pending.subjectHidden")}</p>
                    <p className="rv-meta">
                      {t("pending.recipient")}
                      {agentForDid(agents, message.recipient_did)?.label ?? t("pending.unknownAgent")}
                      {" · "}
                      {t("pending.trustScore", { n: Math.round(message.trust_score * 100) })}
                      {message.ai_category
                        ? t("pending.category", {
                            category: t(
                              message.ai_category === "spam_denylist" || message.ai_category === "spam_burst"
                                ? `pending.categoryName.${message.ai_category}`
                                : "pending.categoryName.other",
                            ),
                          })
                        : ""}
                    </p>
                    <div className="dm-btns">
                      <button
                        className="dm-btn primary"
                        type="button"
                        onClick={() => handleApprove(message.id)}
                        disabled={updateFlags.isPending}
                      >
                        {t("pending.approve")}
                      </button>
                      <button
                        className="dm-btn"
                        type="button"
                        onClick={() => {
                          setBlockStatus(null);
                          setBlockingId(blockingId === message.id ? null : message.id);
                        }}
                        aria-expanded={blockingId === message.id}
                      >
                        {t("pending.block")}
                      </button>
                      <button
                        className="dm-btn"
                        type="button"
                        onClick={() => handleReject(message.id)}
                        disabled={updateFlags.isPending}
                      >
                        {t("pending.reject")}
                      </button>
                    </div>
                    {blockingId === message.id ? (
                      <BlockSenderPanel
                        messageId={message.id}
                        onClose={() => setBlockingId(null)}
                        onResult={setBlockStatus}
                      />
                    ) : null}
                  </div>
                </div>
              );
            })
          )}
          {blockStatus ? (
            <p
              className={"rv-status" + (blockStatus.kind === "error" ? " error" : "")}
              role="status"
            >
              {blockStatus.text}
            </p>
          ) : null}
          {statusMessage ? (
            <p className="rv-status" role="status">
              {statusMessage}
            </p>
          ) : null}
        </section>
      </div>
    </AppShell>
  );
}
