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

  const levelLabels: Record<BlockLevel, string> = {
    l1_did: t("blocks.l1Label"),
    l2_identity: t("blocks.l2Label"),
    l3_stealth: t("blocks.l3Label"),
  };
  const levelDescriptions: Record<BlockLevel, string> = {
    l1_did: t("blocks.l1Desc"),
    l2_identity: t("blocks.l2Desc"),
    l3_stealth: t("blocks.l3Desc"),
  };

  const [level, setLevel] = useState<BlockLevel>("l1_did");
  const [targetDid, setTargetDid] = useState("");
  const [targetWorldId, setTargetWorldId] = useState("");
  const [statusMessage, setStatusMessage] = useState("");

  const blocks = blocksQuery.data?.blocks ?? [];
  const contactsByDid = useMemo(
    () => indexContactsByDid(contactsQuery.data?.contacts),
    [contactsQuery.data],
  );

  const handleCreate = async () => {
    setStatusMessage("");
    try {
      if (level === "l1_did") {
        const did = targetDid.trim();
        if (!did) {
          setStatusMessage(t("blocks.validationDid"));
          return;
        }
        await createBlock.mutateAsync({ level, target_did: did });
      } else {
        const wid = targetWorldId.trim();
        if (!wid) {
          setStatusMessage(t("blocks.validationWorldId"));
          return;
        }
        await createBlock.mutateAsync({ level, target_world_id: wid });
      }
      setTargetDid("");
      setTargetWorldId("");
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
          <label className="ap-field">
            {t("blocks.levelTitle")}
            <select
              className="select"
              value={level}
              onChange={(event) => setLevel(event.target.value as BlockLevel)}
            >
              <option value="l1_did">{levelLabels.l1_did}</option>
              <option value="l2_identity">{levelLabels.l2_identity}</option>
              <option value="l3_stealth">{levelLabels.l3_stealth}</option>
            </select>
          </label>
          <p className="ct-help">{levelDescriptions[level]}</p>
          {level === "l1_did" ? (
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
          ) : (
            <label className="ap-field" htmlFor="block-target-world-id">
              {t("blocks.worldIdTitle")}
              <input
                id="block-target-world-id"
                className="input"
                value={targetWorldId}
                onChange={(event) => setTargetWorldId(event.target.value)}
                placeholder={t("blocks.worldIdPlaceholder")}
                spellCheck={false}
                autoComplete="off"
              />
            </label>
          )}
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
