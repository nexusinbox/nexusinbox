"use client";

// One AI draft, opened from Home (docs/33 §8, §9; docs/41 §6.2). A cloud AI
// cannot send: it leaves a draft, encrypted so that only the devices on the
// agent's signed list can read it (docs/40 §16.3), and the person sends it
// from here.

import { useEffect, useState } from "react";
import { useAgentsQuery, useDeleteAgentDraftMutation, useSendAgentDraftMutation } from "../../../lib/api/hooks";
import type { AgentDraft } from "../../../lib/api/types";
import { formatPartyLabel } from "../../../lib/api/labels";
import { draftDeviceWraps, openDraftHere, senderCopyForDraft, type OpenedDraft } from "../../../lib/crypto/review-key";
import { isSendStop, type SendStop } from "../../../lib/crypto/device-wraps";
import { useTranslation } from "../../../lib/i18n";
import { SendStopNotice } from "../messages/SendStopNotice";

export function draftRecipientName(d: AgentDraft, t: (key: string) => string): string {
  return d.recipient_label ? formatPartyLabel(d.recipient_label, t) : t("agentDrafts.unknownParty");
}

export function DraftReview({ draft, onDone }: { draft: AgentDraft; onDone: (text: string) => void }) {
  const { t } = useTranslation();
  const sendDraft = useSendAgentDraftMutation();
  const deleteDraft = useDeleteAgentDraftMutation();
  const agentsQuery = useAgentsQuery();
  // undefined: still opening; null: this browser cannot read it.
  const [plain, setPlain] = useState<OpenedDraft | null | undefined>(undefined);
  const [failed, setFailed] = useState<string | null>(null);
  // A send stopped by the recipient's device list (docs/40 §12.5).
  const [sendStop, setSendStop] = useState<SendStop | null>(null);

  useEffect(() => {
    let cancelled = false;
    void openDraftHere(draft).then((opened) => {
      if (!cancelled) setPlain(opened);
    });
    return () => {
      cancelled = true;
    };
  }, [draft]);

  const senderName = draft.sender_label ?? t("agentDrafts.unknownParty");
  const name = draftRecipientName(draft, t);

  const send = async (acceptRoot?: string) => {
    setFailed(null);
    setSendStop(null);
    try {
      const senderEncryptedKey = await senderCopyForDraft(draft, plain, agentsQuery.data?.agents ?? []);
      const wraps = await draftDeviceWraps(draft, plain, acceptRoot);
      await sendDraft.mutateAsync({ id: draft.id, senderEncryptedKey, ...wraps });
      onDone(t("agentDrafts.sent"));
    } catch (error) {
      if (isSendStop(error)) {
        setSendStop(error);
        return;
      }
      setFailed(t("agentDrafts.sendFailed"));
    }
  };

  const discard = async () => {
    setFailed(null);
    try {
      await deleteDraft.mutateAsync(draft.id);
      onDone(t("agentDrafts.discarded"));
    } catch {
      setFailed(t("agentDrafts.discardFailed"));
    }
  };

  return (
    <div className="home-expand" data-testid="agent-draft-row">
      <div className="home-muted">
        {draft.via ? t("agentDrafts.madeByVia", { via: draft.via, agent: senderName }) : t("agentDrafts.madeBy", { agent: senderName })}
      </div>
      {plain === undefined ? (
        <p className="home-muted">{t("messages.loadingBody")}</p>
      ) : plain ? (
        <div className="home-bubble">
          {plain.subject ? <div className="dm-subject">{plain.subject}</div> : null}
          {plain.body}
        </div>
      ) : (
        <p className="home-muted" data-testid="agent-draft-unreadable">
          {t("agentDrafts.notHere", { agent: senderName })}
        </p>
      )}
      {sendStop ? (
        <SendStopNotice
          stop={sendStop}
          name={name}
          ownAgent={agentsQuery.data?.agents.find((a) => a.aid === draft.aid)}
          onClose={() => setSendStop(null)}
          onAccept={(root) => void send(root)}
        />
      ) : null}
      <div className="home-acts">
        <button type="button" className="home-btn primary" onClick={() => void send()} disabled={!plain || sendDraft.isPending}>
          {t("agentDrafts.send")}
        </button>
        <button type="button" className="home-btn" onClick={() => void discard()} disabled={deleteDraft.isPending}>
          {t("agentDrafts.discard")}
        </button>
      </div>
      <p className="home-muted" style={{ margin: 0 }}>
        {t("agentDrafts.detailNote")}
      </p>
      {failed ? (
        <p role="status" className="home-note" style={{ margin: 0, color: "var(--danger)" }}>
          {failed}
        </p>
      ) : null}
    </div>
  );
}
