"use client";

// ブロック中: everyone you blocked, under Contacts, with a way to unblock.
// Blocking normally starts from a conversation's ⋯ menu; the manual form
// (raw address or World ID hash) is tucked away for the rare case.

import { useMemo, useState } from "react";
import { AppShell } from "../../_components/AppShell";
import { Avatar } from "../../_components/messages/ConversationView";
import { RefreshIconButton } from "../../_components/RefreshIconButton";
import { ContactsTabs } from "../../contacts/ContactsTabs";
import {
  useBlocksQuery,
  useContactsQuery,
  useCreateBlockMutation,
  useDeleteBlockMutation,
} from "../../../lib/api/hooks";
import {
  formatPartyLabel,
  indexContactsByDid,
  resolveParticipantLabel,
} from "../../../lib/api/labels";
import type { BlockLevel } from "../../../lib/api/types";
import { formatListTimestamp } from "../../../lib/format/messageTime";
import { useTranslation } from "../../../lib/i18n";

export default function BlocksSettingsPage() {
  const { t, locale } = useTranslation();
  const blocksQuery = useBlocksQuery();
  const contactsQuery = useContactsQuery();
  const createBlock = useCreateBlockMutation();
  const deleteBlock = useDeleteBlockMutation();

  // Blocks made as "hide completely" do what the person-wide block does
  // (docs/05 §1.4), and are shown as one.
  const levelLabels: Record<BlockLevel, string> = {
    l1_did: t("blocks.l1Label"),
    l2_identity: t("blocks.l2Label"),
    l3_stealth: t("blocks.l2Label"),
  };

  const [targetDid, setTargetDid] = useState("");
  const [statusMessage, setStatusMessage] = useState("");

  const blocks = blocksQuery.data?.blocks ?? [];
  const contactsByDid = useMemo(
    () => indexContactsByDid(contactsQuery.data?.contacts),
    [contactsQuery.data],
  );

  const handleCreate = async () => {
    setStatusMessage("");
    try {
      const did = targetDid.trim();
      if (!did) {
        setStatusMessage(t("blocks.validationDid"));
        return;
      }
      await createBlock.mutateAsync({ level: "l1_did", target_did: did });
      setTargetDid("");
      setStatusMessage(t("blocks.added"));
    } catch {
      setStatusMessage(t("blocks.addFailed"));
    }
  };

  const handleDelete = async (id: string) => {
    setStatusMessage("");
    try {
      await deleteBlock.mutateAsync(id);
      setStatusMessage(t("blocks.removed"));
    } catch {
      setStatusMessage(t("blocks.removeFailed"));
    }
  };

  return (
    <AppShell
      title={t("contacts.title")}
      activePath="/contacts"
      rightAction={
        <RefreshIconButton onClick={() => blocksQuery.refetch()} label={t("blocks.refresh")} />
      }
    >
      <div className="ct">
        <ContactsTabs active="blocks" />
        <p className="ct-help bl-lead">{t("blocks.lead")}</p>
        {statusMessage ? (
          <p className="ct-status" role="status">
            {statusMessage}
          </p>
        ) : null}

        {blocks.length === 0 ? (
          <p className="bl-empty">{t("blocks.empty")}</p>
        ) : (
          <ul className="bl-list">
            {blocks.map((block) => {
              // An address block names one agent; a World ID block covers
              // every agent of that person, whom we cannot name.
              const name = block.target_did
                ? formatPartyLabel(
                    resolveParticipantLabel(block.target_did, null, contactsByDid),
                    t,
                  )
                : t("blocks.personAllAgents");
              return (
                <li key={block.id} className="dm-row bl-row">
                  {block.target_did ? (
                    <Avatar did={block.target_did} name={name} />
                  ) : (
                    <span className="dm-av bl-av" aria-hidden="true">
                      ⦸
                    </span>
                  )}
                  <span className="dm-row-body">
                    <span className="dm-line1">
                      <span className="dm-name">{name}</span>
                    </span>
                    <span className="bl-meta">
                      {levelLabels[block.level]} ·{" "}
                      {t("blocks.since", {
                        when: formatListTimestamp(block.created_at, { locale }),
                      })}
                    </span>
                  </span>
                  <button
                    className="dm-btn"
                    type="button"
                    onClick={() => handleDelete(block.id)}
                    disabled={deleteBlock.isPending}
                    data-testid="blocks-unblock"
                  >
                    {t("blocks.unblock")}
                  </button>
                </li>
              );
            })}
          </ul>
        )}

        <details className="bl-manual">
          <summary>{t("blocks.addTitle")}</summary>
          <p className="ct-help">{t("blocks.addMeta")}</p>
          <p className="ct-help">{t("blocks.manualScope")}</p>
          <p className="ct-help">{t("blocks.l1Desc")}</p>
          <label className="ap-field" htmlFor="block-target-did">
            {t("blocks.didTitle")}
            <input
              id="block-target-did"
              className="input"
              value={targetDid}
              onChange={(event) => setTargetDid(event.target.value)}
              placeholder={t("blocks.didPlaceholder")}
              spellCheck={false}
              autoComplete="off"
            />
          </label>
          <button
            className="dm-btn primary"
            type="button"
            onClick={handleCreate}
            disabled={createBlock.isPending}
          >
            {t("blocks.addBtn")}
          </button>
        </details>
      </div>
    </AppShell>
  );
}
