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
import { formatPartyLabel } from "../../lib/api/labels";
import {
  findThisBrowsersReviewKey,
  forgetReviewKey,
  openDraft,
  draftDeviceWraps,
  senderCopyForDraft,
  type OpenedDraft,
} from "../../lib/crypto/review-key";
import { formatListTimestamp } from "../../lib/format/messageTime";
import { useTranslation } from "../../lib/i18n";
import { Avatar } from "../_components/messages/ConversationView";
import { SendStopNotice } from "../_components/messages/SendStopNotice";
import { isSendStop, type SendStop } from "../../lib/crypto/device-wraps";

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
  const [status, setStatus] = useState("");
  // A send stopped by the recipient's device list (docs/40 §12.5), by draft.
  const [sendStop, setSendStop] = useState<{ draftId: string; stop: SendStop } | null>(null);

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

  const handleSend = async (draft: AgentDraft, acceptRoot?: string) => {
    setStatus("");
    setSendStop(null);
    try {
      const senderEncryptedKey = await senderCopyForDraft(
        draft,
        opened[draft.id],
        agentsQuery.data?.agents ?? [],
      );
      const wraps = await draftDeviceWraps(draft, opened[draft.id], acceptRoot);
      await sendDraft.mutateAsync({ id: draft.id, senderEncryptedKey, ...wraps });
      setStatus(t("agentDrafts.sent"));
    } catch (error) {
      if (isSendStop(error)) {
        setSendStop({ draftId: draft.id, stop: error });
        return;
      }
      setStatus(t("agentDrafts.sendFailed"));
    }
  };

  const handleDiscard = async (draft: AgentDraft) => {
    setStatus("");
    try {
      await deleteDraft.mutateAsync(draft.id);
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

  const recipientName = (d: AgentDraft) =>
    d.recipient_label ? formatPartyLabel(d.recipient_label, t) : t("agentDrafts.unknownParty");
  const senderName = (d: AgentDraft) => d.sender_label ?? t("agentDrafts.unknownParty");
  const madeBy = (d: AgentDraft) =>
    d.via
      ? t("agentDrafts.madeByVia", { via: d.via, agent: senderName(d) })
      : t("agentDrafts.madeBy", { agent: senderName(d) });

  return (
    <section className="rv-section" data-testid="agent-drafts">
      <h3 className="rv-title">{t("agentDrafts.title", { count: drafts.length })}</h3>
      <p className="rv-why">{t("agentDrafts.why")}</p>

      {keyChecked && !myKey ? (
        <div className="rv-setup">
          <p style={{ margin: 0 }}>
            {drafts.length > 0 ? t("agentDrafts.notSetUpWithDrafts") : t("agentDrafts.notSetUp")}
          </p>
          <p className="dm-muted" style={{ margin: "4px 0 8px" }}>{t("agentDrafts.setUpHow")}</p>
          <button
            className="dm-btn accent"
            type="button"
            onClick={handleSetUp}
            disabled={createKey.isPending}
          >
            {t("agentDrafts.setUp")}
          </button>
        </div>
      ) : null}

      {draftsQuery.isError ? (
        <p className="rv-empty" style={{ color: "var(--danger)" }}>
          {t("agentDrafts.loadFailed")}
        </p>
      ) : drafts.length === 0 ? (
        <p className="rv-empty">{t("agentDrafts.empty")}</p>
      ) : (
        drafts.map((draft) => {
          const plain = opened[draft.id];
          const name = recipientName(draft);
          return (
            <div key={draft.id} className="rv-row" data-testid="agent-draft-row">
              <Avatar did={draft.recipient_did} name={name} />
              <div className="dm-row-body">
                <div className="dm-line1">
                  <span className="dm-name">
                    {draft.in_reply_to
                      ? t("agentDrafts.replyTo", { name })
                      : t("agentDrafts.newTo", { name })}
                  </span>
                  <span className="dm-time">
                    {formatListTimestamp(draft.created_at, { locale })}
                  </span>
                </div>
                <div className="dm-draft rv-card">
                  <div className="dm-muted">✍︎ {madeBy(draft)}</div>
                  {plain === undefined && myKey ? (
                    <p className="dm-muted">{t("messages.loadingBody")}</p>
                  ) : plain ? (
                    <>
                      {plain.subject ? <div className="dm-subject">{plain.subject}</div> : null}
                      <p className="dm-draft-body">{plain.body}</p>
                    </>
                  ) : (
                    <p className="dm-muted">
                      {myKey ? t("agentDrafts.unreadableBody") : t("agentDrafts.unreadable")}
                    </p>
                  )}
                  {sendStop?.draftId === draft.id ? (
                    <SendStopNotice
                      stop={sendStop.stop}
                      name={name}
                      onClose={() => setSendStop(null)}
                      onAccept={(root) => void handleSend(draft, root)}
                    />
                  ) : null}
                  <div className="dm-btns">
                    <button
                      className="dm-btn accent"
                      type="button"
                      onClick={() => handleSend(draft)}
                      disabled={!plain || sendDraft.isPending}
                    >
                      {t("agentDrafts.send")}
                    </button>
                    <button
                      className="dm-btn"
                      type="button"
                      onClick={() => handleDiscard(draft)}
                      disabled={deleteDraft.isPending}
                    >
                      {t("agentDrafts.discard")}
                    </button>
                  </div>
                </div>
              </div>
            </div>
          );
        })
      )}
      {drafts.length > 0 ? <p className="rv-why">{t("agentDrafts.detailNote")}</p> : null}

      {keys.length > 0 ? (
        <details className="rv-browsers">
          <summary>
            {t("agentDrafts.browsers", { count: keys.length })}
          </summary>
          {keys.map((key) => (
            <div
              key={key.id}
              className="rv-browser"
            >
              <span>
                {key.label}
                {myKey?.id === key.id ? ` (${t("agentDrafts.thisBrowser")})` : ""} ·{" "}
                {formatListTimestamp(key.created_at, { locale })}
              </span>
              <button
                className="dm-btn"
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
      {status ? (
        <p className="rv-status" role="status">
          {status}
        </p>
      ) : null}
    </section>
  );
}
