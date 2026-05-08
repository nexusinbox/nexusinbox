"use client";

import { useMemo, useState } from "react";
import { AppShell } from "../_components/AppShell";
import { RefreshIconButton } from "../_components/RefreshIconButton";
import {
  useAgentsQuery,
  useMessagesQuery,
  useUpdateMessageFlagsMutation,
} from "../../lib/api/hooks";
import { useTwoColumnResize } from "../../lib/ui/useTwoColumnResize";
import { formatParticipant } from "../../lib/api/client";
import { useTranslation } from "../../lib/i18n";
import { formatListTimestamp } from "../../lib/format/messageTime";

export default function PendingApprovalPage() {
  const { t, locale } = useTranslation();
  const agentsQuery = useAgentsQuery();
  const agents = agentsQuery.data?.agents ?? [];
  const [activeDid, setActiveDid] = useState<string>("all");
  const [statusMessage, setStatusMessage] = useState<string>("");
  const { layoutStyle, startResize } = useTwoColumnResize({
    storageKey: "nexusinbox.pending.thread_width.v1",
    initialWidth: 320,
  });

  const selectedDid = activeDid || "all";

  // Server-side folder filter: only messages the AI spam pipeline or
  // low trust routing put into the pending_approval bucket show up here.
  const messagesQuery = useMessagesQuery({
    agentDid: selectedDid,
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
      <section className="mail-layout" style={layoutStyle}>
        <aside className="thread-list">
          <div className="panel" style={{ margin: 12 }}>
            <p className="item-title">{t("pending.selectAgent")}</p>
            <select
              className="select"
              value={selectedDid}
              onChange={(event) => setActiveDid(event.target.value)}
              style={{ marginTop: 6, width: "100%" }}
            >
              <option value="all">{t("pending.allAgents")}</option>
              {agents.map((agent) => (
                <option key={agent.id} value={agent.did}>
                  {agent.label}
                </option>
              ))}
            </select>
          </div>
        </aside>

        <div className="mail-resizer" onMouseDown={startResize} />

        <article className="reader-pane" style={{ borderRight: "none" }}>
          <header className="reader-header">
            <h2 className="reader-subject">{t("pending.heading", { count: pending.length })}</h2>
            <p className="reader-meta">
              {selectedDid
                ? t("pending.descSelected")
                : t("pending.descUnselected")}
            </p>
          </header>

          <div className="reader-body">
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
              <div className="empty-state">{t("pending.empty")}</div>
            ) : (
              pending.map((message) => (
                <div className="panel" key={message.id} style={{ marginTop: 10 }}>
                  <p className="item-title">
                    {message.subject_encrypted || t("pending.noSubject")}
                  </p>
                  <p className="item-sub">
                    {t("pending.sender")}{formatParticipant(message.sender_label, message.sender_did)}
                  </p>
                  <p className="item-sub">
                    {t("pending.trustScore", { n: Math.round(message.trust_score * 100) })}
                    {message.ai_category ? t("pending.category", { category: message.ai_category }) : ""}
                  </p>
                  <p className="item-sub">
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
          </div>
        </article>
      </section>
    </AppShell>
  );
}
