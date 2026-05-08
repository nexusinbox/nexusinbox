"use client";

import { useState } from "react";
import { AppShell } from "../../_components/AppShell";
import { RefreshIconButton } from "../../_components/RefreshIconButton";
import {
  useBlocksQuery,
  useCreateBlockMutation,
  useDeleteBlockMutation,
} from "../../../lib/api/hooks";
import type { BlockLevel } from "../../../lib/api/types";
import { useTwoColumnResize } from "../../../lib/ui/useTwoColumnResize";
import { useTranslation } from "../../../lib/i18n";

export default function BlocksSettingsPage() {
  const { t } = useTranslation();
  const blocksQuery = useBlocksQuery();
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
  const { layoutStyle, startResize } = useTwoColumnResize({
    storageKey: "nexusinbox.settings_blocks.thread_width.v1",
    initialWidth: 380,
  });

  const blocks = blocksQuery.data?.blocks ?? [];

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
      title={t("blocks.title")}
      activePath="/settings/blocks"
      rightAction={
        <RefreshIconButton
          onClick={() => blocksQuery.refetch()}
          label={t("blocks.refresh")}
        />
      }
    >
      <section className="mail-layout" style={layoutStyle}>
        <aside className="thread-list">
          {blocks.length === 0 ? (
            <div className="empty-state" style={{ padding: 16 }}>
              {t("blocks.empty")}
            </div>
          ) : (
            blocks.map((block) => {
              // Tag the card with whether the stored target is an
              // Agent Address (DID) or a sender's World ID — the raw
              // value alone (did:key:... vs 0x...) leaves users
              // guessing which identifier space they're looking at.
              const targetBadge = block.target_did
                ? t("blocks.targetDidBadge")
                : block.target_world_id
                  ? t("blocks.targetWorldIdBadge")
                  : null;
              const targetValue =
                block.target_did ?? block.target_world_id ?? "-";
              return (
                <article className="card-item" key={block.id}>
                  <p className="card-title">{levelLabels[block.level]}</p>
                  <p
                    className="card-sub"
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 6,
                      wordBreak: "break-all",
                    }}
                  >
                    {targetBadge ? (
                      <span
                        style={{
                          fontSize: 10,
                          fontWeight: 500,
                          padding: "1px 6px",
                          borderRadius: 999,
                          letterSpacing: 0.3,
                          whiteSpace: "nowrap",
                          background: "rgba(128, 128, 128, 0.14)",
                          color: "#5f6368",
                          border: "1px solid rgba(128, 128, 128, 0.28)",
                          flexShrink: 0,
                        }}
                      >
                        {targetBadge}
                      </span>
                    ) : null}
                    <span>{targetValue}</span>
                  </p>
                  <p className="card-meta">
                    <span>{new Date(block.created_at).toLocaleString()}</span>
                  </p>
                  <button
                    className="btn"
                    type="button"
                    onClick={() => handleDelete(block.id)}
                    disabled={deleteBlock.isPending}
                    style={{ marginTop: 4 }}
                  >
                    {t("blocks.unblock")}
                  </button>
                </article>
              );
            })
          )}
        </aside>

        <div className="mail-resizer" onMouseDown={startResize} />

        <article className="reader-pane" style={{ borderRight: "none" }}>
          <header className="reader-header">
            <h2 className="reader-subject">{t("blocks.addTitle")}</h2>
            <p className="reader-meta">{t("blocks.addMeta")}</p>
          </header>

          <div className="reader-body">
            <div className="panel">
              <p className="item-title">{t("blocks.levelTitle")}</p>
              <select
                className="select"
                value={level}
                onChange={(event) => setLevel(event.target.value as BlockLevel)}
                style={{ marginTop: 6, width: "100%" }}
              >
                <option value="l1_did">{levelLabels.l1_did}</option>
                <option value="l2_identity">{levelLabels.l2_identity}</option>
                <option value="l3_stealth">{levelLabels.l3_stealth}</option>
              </select>
              <p className="item-sub" style={{ marginTop: 8 }}>
                {levelDescriptions[level]}
              </p>
            </div>

            {level === "l1_did" ? (
              <div className="panel" style={{ marginTop: 10 }}>
                <label
                  htmlFor="block-target-did"
                  className="item-title"
                  style={{ display: "block" }}
                >
                  {t("blocks.didTitle")}
                </label>
                <input
                  id="block-target-did"
                  className="input"
                  value={targetDid}
                  onChange={(event) => setTargetDid(event.target.value)}
                  placeholder={t("blocks.didPlaceholder")}
                  spellCheck={false}
                  autoComplete="off"
                  style={{
                    marginTop: 6,
                    fontFamily: "ui-monospace, monospace",
                  }}
                />
                <p
                  className="item-sub"
                  style={{ marginTop: 6, lineHeight: 1.5 }}
                >
                  {t("blocks.didHelp")}
                </p>
              </div>
            ) : (
              <div className="panel" style={{ marginTop: 10 }}>
                <label
                  htmlFor="block-target-world-id"
                  className="item-title"
                  style={{ display: "block" }}
                >
                  {t("blocks.worldIdTitle")}
                </label>
                <input
                  id="block-target-world-id"
                  className="input"
                  value={targetWorldId}
                  onChange={(event) => setTargetWorldId(event.target.value)}
                  placeholder={t("blocks.worldIdPlaceholder")}
                  spellCheck={false}
                  autoComplete="off"
                  style={{
                    marginTop: 6,
                    fontFamily: "ui-monospace, monospace",
                  }}
                />
                <p
                  className="item-sub"
                  style={{ marginTop: 6, lineHeight: 1.5 }}
                >
                  {t("blocks.worldIdHelp")}
                </p>
              </div>
            )}

            <div className="row" style={{ marginTop: 12 }}>
              <button
                className="btn primary"
                type="button"
                onClick={handleCreate}
                disabled={createBlock.isPending}
              >
                {t("blocks.addBtn")}
              </button>
              {statusMessage ? (
                <span className="item-sub">{statusMessage}</span>
              ) : null}
            </div>
          </div>
        </article>
      </section>
    </AppShell>
  );
}
