"use client";

import { useMemo, useState } from "react";
import { AppShell } from "../_components/AppShell";
import { AgentDrafts } from "./AgentDrafts";
import { agentForDid } from "../_components/InboxAgentBar";
import { RefreshIconButton } from "../_components/RefreshIconButton";
import {
  useAgentsQuery,
  useContactsQuery,
  useMessagesQuery,
  useUpdateMessageFlagsMutation,
} from "../../lib/api/hooks";
import { indexContactsByDid, resolveParticipantLabel } from "../../lib/api/labels";
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
      <section style={{ padding: "8px 16px 32px", maxWidth: 880 }}>
        <AgentDrafts />

        <section className="panel" style={{ marginTop: 16 }} data-testid="pending-messages">
          <h3 style={{ margin: "4px 0 2px", fontSize: 16, fontWeight: 700 }}>
            {t("pending.heading", { count: pending.length })}
          </h3>
          <p style={{ margin: "0 0 8px", fontSize: 13, color: "#6b7280" }}>
            {t("pending.descSelected")}
          </p>
          {messagesQuery.isLoading ? (
            <div className="empty-state">{t("pending.loading")}</div>
          ) : messagesQuery.isError ? (
            <div className="empty-state" style={{ color: "#ef4444" }}>
              {t("pending.error")}
              <button
                className="btn"
                type="button"
                onClick={() => messagesQuery.refetch()}
                style={{ marginTop: 8 }}
              >
                {t("pending.retry")}
              </button>
            </div>
          ) : pending.length === 0 ? (
            <p className="item-sub">{t("pending.empty")}</p>
          ) : (
            pending.map((message) => (
              <div
                key={message.id}
                data-testid="pending-row"
                style={{ borderTop: "1px solid #e5e7eb", padding: "10px 0" }}
              >
                {/* The subject is encrypted for the recipient agent; it can be
                    read in the inbox once approved. */}
                <p className="item-title">{t("pending.subjectHidden")}</p>
                <p className="item-sub">
                  {t("pending.sender")}
                  {resolveParticipantLabel(message.sender_did, message.sender_label, contactsByDid)}
                  {" · "}
                  {t("pending.recipient")}
                  {agentForDid(agents, message.recipient_did)?.label ?? t("pending.unknownAgent")}
                </p>
                <p className="item-sub">
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
                  {" · "}
                  {formatListTimestamp(message.created_at, { locale })}
                </p>
                <div className="row" style={{ marginTop: 8, gap: 8 }}>
                  <button
                    className="btn primary"
                    type="button"
                    onClick={() => handleApprove(message.id)}
                    disabled={updateFlags.isPending}
                  >
                    {t("pending.approve")}
                  </button>
                  <button
                    className="btn"
                    type="button"
                    onClick={() => handleReject(message.id)}
                    disabled={updateFlags.isPending}
                  >
                    {t("pending.reject")}
                  </button>
                </div>
              </div>
            ))
          )}
          {statusMessage ? (
            <p className="item-sub" style={{ marginTop: 12 }}>
              {statusMessage}
            </p>
          ) : null}
        </section>
      </section>
    </AppShell>
  );
}
