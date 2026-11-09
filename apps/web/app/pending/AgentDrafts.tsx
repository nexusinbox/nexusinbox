"use client";

// AI drafts waiting for the person (docs/33 §8, §9). A cloud AI cannot
// send: it leaves a draft, encrypted so that only browsers set up here can
// read it, and the person sends it from this section.

import { useEffect, useMemo, useState } from "react";
import {
  useAgentDraftsQuery,
  useAgentsQuery,
  useCreateReviewKeyMutation,
  useDeleteAgentDraftMutation,
  useDeleteReviewKeyMutation,
  useReviewKeysQuery,
  useSendAgentDraftMutation,
} from "../../lib/api/hooks";
import type { AgentDraft, ReviewKey } from "../../lib/api/types";
import {
  findThisBrowsersReviewKey,
  forgetReviewKey,
  openDraft,
  senderCopyForDraft,
  type OpenedDraft,
} from "../../lib/crypto/review-key";
import { formatListTimestamp } from "../../lib/format/messageTime";
import { useTranslation } from "../../lib/i18n";

const sectionTitle: React.CSSProperties = { margin: "4px 0 2px", fontSize: 16, fontWeight: 700 };
const why: React.CSSProperties = { margin: "0 0 8px", fontSize: 13, color: "#6b7280" };
const bodyBox: React.CSSProperties = {
  border: "1px solid #e5e7eb",
  borderRadius: 10,
  padding: "12px 14px",
  background: "#fbfcfe",
  whiteSpace: "pre-wrap",
  overflowWrap: "anywhere",
  fontSize: 14,
  margin: "10px 0",
};
const metaGrid: React.CSSProperties = {
  display: "grid",
  gridTemplateColumns: "6em minmax(0, 1fr)",
  gap: "4px 10px",
  fontSize: 14,
};
const muted: React.CSSProperties = { color: "#6b7280", fontSize: 13 };

export function AgentDrafts() {
  const { t, locale } = useTranslation();
  const draftsQuery = useAgentDraftsQuery();
  const keysQuery = useReviewKeysQuery();
  const createKey = useCreateReviewKeyMutation();
  const deleteKey = useDeleteReviewKeyMutation();
  const sendDraft = useSendAgentDraftMutation();
  const deleteDraft = useDeleteAgentDraftMutation();
  const agentsQuery = useAgentsQuery();

  const drafts = useMemo(() => draftsQuery.data?.drafts ?? [], [draftsQuery.data]);
  const keys = useMemo(() => keysQuery.data?.review_keys ?? [], [keysQuery.data]);
  const [myKey, setMyKey] = useState<ReviewKey | null>(null);
  const [keyChecked, setKeyChecked] = useState(false);
  const [opened, setOpened] = useState<Record<string, OpenedDraft | null>>({});
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [status, setStatus] = useState("");

  useEffect(() => {
    let cancelled = false;
    findThisBrowsersReviewKey(keys).then((key) => {
      if (cancelled) return;
      setMyKey(key);
      setKeyChecked(true);
    });
    return () => {
      cancelled = true;
    };
  }, [keys]);

  useEffect(() => {
    if (!myKey) return;
    let cancelled = false;
    const missing = drafts.filter((d) => !(d.id in opened));
    if (missing.length === 0) return;
    Promise.all(missing.map(async (d) => [d.id, await openDraft(d, myKey.id)] as const)).then(
      (pairs) => {
        if (cancelled) return;
        setOpened((prev) => ({ ...prev, ...Object.fromEntries(pairs) }));
      },
    );
    return () => {
      cancelled = true;
    };
  }, [drafts, myKey, opened]);

  const selected = drafts.find((d) => d.id === selectedId) ?? null;

  const handleSetUp = async () => {
    setStatus("");
    try {
      await createKey.mutateAsync();
      setOpened({});
      setStatus(t("agentDrafts.setUpDone"));
    } catch {
      setStatus(t("agentDrafts.setUpFailed"));
    }
  };

  const handleSend = async (draft: AgentDraft) => {
    setStatus("");
    try {
      const senderEncryptedKey = await senderCopyForDraft(
        draft,
        opened[draft.id],
        agentsQuery.data?.agents ?? [],
      );
      await sendDraft.mutateAsync({ id: draft.id, senderEncryptedKey });
      setSelectedId(null);
      setStatus(t("agentDrafts.sent"));
    } catch {
      setStatus(t("agentDrafts.sendFailed"));
    }
  };

  const handleDiscard = async (draft: AgentDraft) => {
    setStatus("");
    try {
      await deleteDraft.mutateAsync(draft.id);
      setSelectedId(null);
      setStatus(t("agentDrafts.discarded"));
    } catch {
      setStatus(t("agentDrafts.discardFailed"));
    }
  };

  const handleRemoveKey = async (key: ReviewKey) => {
    setStatus("");
    try {
      await deleteKey.mutateAsync(key.id);
      if (myKey?.id === key.id) forgetReviewKey();
    } catch {
      setStatus(t("agentDrafts.removeFailed"));
    }
  };

  const recipientName = (d: AgentDraft) => d.recipient_label ?? t("agentDrafts.unknownParty");
  const senderName = (d: AgentDraft) => d.sender_label ?? t("agentDrafts.unknownParty");
  const madeBy = (d: AgentDraft) =>
    d.via
      ? t("agentDrafts.madeByVia", { via: d.via, agent: senderName(d) })
      : t("agentDrafts.madeBy", { agent: senderName(d) });

  if (selected) {
    const plain = opened[selected.id];
    return (
      <section className="panel" style={{ marginTop: 10 }} data-testid="agent-draft-detail">
        <div className="row" style={{ justifyContent: "space-between", gap: 8 }}>
          <h3 style={sectionTitle}>{t("agentDrafts.detailTitle")}</h3>
          <button className="btn" type="button" onClick={() => setSelectedId(null)}>
            {t("agentDrafts.back")}
          </button>
        </div>
        <div style={{ ...metaGrid, marginTop: 8 }}>
          <span style={muted}>{t("agentDrafts.from")}</span>
          <span>{senderName(selected)}</span>
          <span style={muted}>{t("agentDrafts.to")}</span>
          <span>{recipientName(selected)}</span>
          <span style={muted}>{t("agentDrafts.subject")}</span>
          <span>{plain ? plain.subject : t("agentDrafts.unreadable")}</span>
          <span style={muted}>{t("agentDrafts.made")}</span>
          <span>
            {madeBy(selected)} · {formatListTimestamp(selected.created_at, { locale })}
          </span>
        </div>
        <div style={bodyBox}>{plain ? plain.body : t("agentDrafts.unreadableBody")}</div>
        <div className="row" style={{ gap: 8 }}>
          <button
            className="btn primary"
            type="button"
            onClick={() => handleSend(selected)}
            disabled={!plain || sendDraft.isPending}
          >
            {t("agentDrafts.send")}
          </button>
          <button
            className="btn"
            type="button"
            onClick={() => handleDiscard(selected)}
            disabled={deleteDraft.isPending}
          >
            {t("agentDrafts.discard")}
          </button>
        </div>
        <p style={{ ...muted, marginTop: 8 }}>{t("agentDrafts.detailNote")}</p>
        {status ? <p className="item-sub">{status}</p> : null}
      </section>
    );
  }

  return (
    <section className="panel" style={{ marginTop: 10 }} data-testid="agent-drafts">
      <h3 style={sectionTitle}>{t("agentDrafts.title", { count: drafts.length })}</h3>
      <p style={why}>{t("agentDrafts.why")}</p>

      {keyChecked && !myKey ? (
        <div
          style={{ background: "#fff6e0", borderRadius: 10, padding: "10px 12px", margin: "8px 0" }}
        >
          <p style={{ margin: 0, fontSize: 14 }}>
            {drafts.length > 0 ? t("agentDrafts.notSetUpWithDrafts") : t("agentDrafts.notSetUp")}
          </p>
          <p style={{ ...muted, margin: "4px 0 8px" }}>{t("agentDrafts.setUpHow")}</p>
          <button
            className="btn primary"
            type="button"
            onClick={handleSetUp}
            disabled={createKey.isPending}
          >
            {t("agentDrafts.setUp")}
          </button>
        </div>
      ) : null}

      {draftsQuery.isError ? (
        <p className="item-sub" style={{ color: "#b3261e" }}>
          {t("agentDrafts.loadFailed")}
        </p>
      ) : drafts.length === 0 ? (
        <p className="item-sub">{t("agentDrafts.empty")}</p>
      ) : (
        drafts.map((draft) => {
          const plain = opened[draft.id];
          return (
            <div
              key={draft.id}
              className="row"
              style={{
                justifyContent: "space-between",
                gap: 8,
                borderTop: "1px solid #e5e7eb",
                padding: "10px 0",
              }}
            >
              <div style={{ minWidth: 0 }}>
                <strong style={{ display: "block", overflowWrap: "anywhere" }}>
                  {plain ? plain.subject : t("agentDrafts.unreadable")}
                </strong>
                <span style={muted}>
                  {t("agentDrafts.to")}: {recipientName(draft)} · {madeBy(draft)} ·{" "}
                  {formatListTimestamp(draft.created_at, { locale })}
                </span>
              </div>
              <button className="btn primary" type="button" onClick={() => setSelectedId(draft.id)}>
                {t("agentDrafts.open")}
              </button>
            </div>
          );
        })
      )}

      {keys.length > 0 ? (
        <details style={{ marginTop: 10 }}>
          <summary style={{ cursor: "pointer", fontSize: 13 }}>
            {t("agentDrafts.browsers", { count: keys.length })}
          </summary>
          {keys.map((key) => (
            <div
              key={key.id}
              className="row"
              style={{ justifyContent: "space-between", gap: 8, padding: "6px 0", fontSize: 13 }}
            >
              <span>
                {key.label}
                {myKey?.id === key.id ? ` (${t("agentDrafts.thisBrowser")})` : ""} ·{" "}
                {formatListTimestamp(key.created_at, { locale })}
              </span>
              <button
                className="btn"
                type="button"
                onClick={() => handleRemoveKey(key)}
                disabled={deleteKey.isPending}
              >
                {t("agentDrafts.removeBrowser")}
              </button>
            </div>
          ))}
        </details>
      ) : null}
      {status ? <p className="item-sub">{status}</p> : null}
    </section>
  );
}
