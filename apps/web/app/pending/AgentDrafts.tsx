"use client";

// AI drafts waiting for the person (docs/33 §8, §9). A cloud AI cannot
// send: it leaves a draft, encrypted so that only the devices on the
// agent's signed list can read it (docs/40 §16.3), and the person sends it
// from this section.

import { useEffect, useMemo, useState } from "react";
import {
  useAgentDraftsQuery,
  useAgentsQuery,
  useDeleteAgentDraftMutation,
  useReviewKeysQuery,
  useSendAgentDraftMutation,
} from "../../lib/api/hooks";
import type { AgentDraft } from "../../lib/api/types";
import { formatPartyLabel } from "../../lib/api/labels";
import {
  openDraftHere,
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
  // Older computers wrapped drafts to browsers set up for review.
  const keysQuery = useReviewKeysQuery();
  const sendDraft = useSendAgentDraftMutation();
  const deleteDraft = useDeleteAgentDraftMutation();
  const agentsQuery = useAgentsQuery();

  const drafts = useMemo(() => draftsQuery.data?.drafts ?? [], [draftsQuery.data]);
  const keys = keysQuery.data?.review_keys;
  const [opened, setOpened] = useState<Record<string, OpenedDraft | null>>({});
  const [status, setStatus] = useState("");
  // A send stopped by the recipient's device list (docs/40 §12.5), by draft.
  const [sendStop, setSendStop] = useState<{ draftId: string; stop: SendStop } | null>(null);

  useEffect(() => {
    if (keysQuery.isLoading) return;
    let cancelled = false;
    const missing = drafts.filter((d) => !(d.id in opened));
    if (missing.length === 0) return;
    Promise.all(missing.map(async (d) => [d.id, await openDraftHere(d, keys)] as const)).then(
      (pairs) => {
        if (cancelled) return;
        setOpened((prev) => ({ ...prev, ...Object.fromEntries(pairs) }));
      },
    );
    return () => {
      cancelled = true;
    };
  }, [drafts, keys, keysQuery.isLoading, opened]);

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
                  {plain === undefined ? (
                    <p className="dm-muted">{t("messages.loadingBody")}</p>
                  ) : plain ? (
                    <>
                      {plain.subject ? <div className="dm-subject">{plain.subject}</div> : null}
                      <p className="dm-draft-body">{plain.body}</p>
                    </>
                  ) : (
                    <p className="dm-muted" data-testid="agent-draft-unreadable">
                      {t("agentDrafts.notHere", { agent: senderName(draft) })}
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

      {status ? (
        <p className="rv-status" role="status">
          {status}
        </p>
      ) : null}
    </section>
  );
}
