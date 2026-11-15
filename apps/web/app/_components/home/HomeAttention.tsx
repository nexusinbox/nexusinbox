"use client";

// 「あなたの判断が必要」 on Home (docs/41 §6.1–§6.2): the inbox notices and
// the old 「確認が必要」 page in one list. One row: kind, who, what, why it
// waits, one action. Drafts and held messages open in place, so nothing
// needs another page.

import Link from "next/link";
import { useMemo, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { elapsed } from "../../../lib/agents/agent-status";
import { formatPartyLabel, indexContactsByDid, resolveParticipantLabel } from "../../../lib/api/labels";
import { queryKeys, useContactsQuery, useUpdateMessageFlagsMutation } from "../../../lib/api/hooks";
import type { Agent, MessageIndexEntry } from "../../../lib/api/types";
import { agentOfItem, attentionKey, canPutOff, groupOf, type AttentionItem } from "../../../lib/home/attention";
import { acceptNewDevices } from "../../../lib/home/device-attention";
import type { Attention } from "../../../lib/home/use-attention";
import { formatListTimestamp } from "../../../lib/format/messageTime";
import { useTranslation } from "../../../lib/i18n";
import { deviceName } from "../AgentDevices";
import { BlockSenderPanel, type BlockStatus } from "../ConversationThread";
import { DraftReview, draftRecipientName } from "./DraftReview";
import { agentPageLink } from "./HomeStatus";
import { CONVERSATIONS_PATH } from "../../../lib/url/conversations";

/** Stopped this long, a computer is likely no longer used: suggest removing it. */
const STALE_AFTER_MS = 30 * 24 * 60 * 60 * 1000;

const TAG_TONE: Record<AttentionItem["kind"], "danger" | "warn" | "info" | ""> = {
  list_wrong: "danger",
  pairing_mismatch: "danger",
  new_device: "danger",
  list_undecided: "warn",
  draft: "info",
  held: "",
  computer_stopped: "",
};

export function HomeAttention({ attention, agents }: { attention: Attention; agents: Agent[] }) {
  const { t } = useTranslation();
  const [showLater, setShowLater] = useState(false);
  const [status, setStatus] = useState<string | null>(null);

  const count = attention.state === "ready" ? attention.count : null;

  return (
    <section className="home-section" id="attention" aria-labelledby="home-attention-title" data-testid="home-attention">
      <div className="home-section-head">
        <h2 id="home-attention-title" className="home-section-title">
          {t("home.attention.title")}
        </h2>
        <span className="home-count" data-testid="home-attention-count">
          {count === null ? "—" : t("home.attention.count", { n: count })}
        </span>
      </div>
      {attention.state === "ready" && attention.breakdown.length > 0 ? (
        <p className="home-breakdown">
          {attention.breakdown.map((b) => t("home.group.count", { group: t(`home.group.${b.group}`), n: b.n })).join("・")}
        </p>
      ) : null}
      <div className="home-box">
        {attention.state === "loading" ? (
          <div className="home-empty">{t("home.loading")}</div>
        ) : attention.state === "error" ? (
          <div className="home-error" data-testid="home-attention-error">
            <span className="home-error-text">
              <b>{t("home.attention.failed")}</b>
              <br />
              <span className="home-muted">{t("home.attention.failedSub")}</span>
            </span>
            <button type="button" className="home-btn" onClick={attention.retry}>
              {t("home.retry")}
            </button>
          </div>
        ) : (
          <>
            {attention.now.length === 0 && attention.heldUnloaded === 0 ? (
              // Only what Home gathers: requests such as scheduling are
              // read in the conversations (docs/41 §13, stage C).
              <div className="home-empty" data-testid="home-attention-none">
                <span className="home-empty-icon" aria-hidden>
                  ✓
                </span>
                <span>
                  {t("home.attention.none")}
                  <br />
                  <Link href={CONVERSATIONS_PATH} className="home-link" style={{ minHeight: 0 }}>
                    {t("home.attention.noneRequests")}
                  </Link>
                </span>
              </div>
            ) : (
              attention.now.map((item) => (
                <AttentionRow
                  key={attentionKey(item)}
                  item={item}
                  agents={agents}
                  onPutOff={canPutOff(item.kind) ? () => attention.putOff(item) : undefined}
                  onDone={(text) => {
                    setStatus(text);
                    attention.refresh();
                  }}
                />
              ))
            )}
            {attention.heldUnloaded > 0 ? (
              // The server counts more held messages than one page reads.
              <div className="home-error" style={{ background: "var(--surface-alt)" }} data-testid="home-attention-more">
                <span className="home-error-text">
                  {attention.narrowed
                    ? t("home.attention.moreHeldAnyAgent", { n: attention.heldUnloaded })
                    : t("home.attention.moreHeld", { n: attention.heldUnloaded })}
                </span>
                <button type="button" className="home-btn" onClick={attention.loadMoreHeld} disabled={attention.loadingMoreHeld}>
                  {attention.loadingMoreHeld ? t("home.loading") : t("home.attention.loadMore")}
                </button>
              </div>
            ) : null}
            {attention.later.length > 0 ? (
              <>
                <button
                  type="button"
                  className="home-folded"
                  aria-expanded={showLater}
                  onClick={() => setShowLater((v) => !v)}
                  data-testid="home-attention-later"
                >
                  {showLater ? "▾ " : "▸ "}
                  {t("home.attention.laterFolded", { n: attention.later.length })}
                </button>
                {showLater
                  ? attention.later.map((item) => (
                      <AttentionRow
                        key={attentionKey(item)}
                        item={item}
                        agents={agents}
                        onDone={(text) => {
                          setStatus(text);
                          attention.refresh();
                        }}
                      />
                    ))
                  : null}
              </>
            ) : null}
          </>
        )}
      </div>
      {status ? (
        <p role="status" className="home-note" style={{ margin: "8px 0 0" }}>
          {status}
        </p>
      ) : null}
    </section>
  );
}

function AttentionRow({
  item,
  agents,
  onPutOff,
  onDone,
}: {
  item: AttentionItem;
  agents: Agent[];
  onPutOff?: () => void;
  onDone: (text: string) => void;
}) {
  const { t, locale } = useTranslation();
  const queryClient = useQueryClient();
  const contactsQuery = useContactsQuery();
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const contacts = useMemo(() => indexContactsByDid(contactsQuery.data?.contacts), [contactsQuery.data]);
  const party = (did: string, label: string | null | undefined) =>
    formatPartyLabel(resolveParticipantLabel(did, label ?? null, contacts), t);
  // With more than one agent, each row says whose it is.
  const chipAgent = agents.length < 2 ? null : agentOfItem(item, agents);

  let what: string;
  let why: string;
  let action: React.ReactNode = null;
  let extra: React.ReactNode = null;

  switch (item.kind) {
    case "list_wrong":
      what = t("deviceList.wrongTitle", { agent: item.agent.label });
      why =
        item.changed.length > 0
          ? t("deviceList.wrongMismatch", { device: item.changed.map((d) => deviceName(t, d)).join("、") })
          : t("deviceList.wrongBroken");
      action = (
        <Link href={agentPageLink(item.agent, item.changed[0]?.did)} className="home-btn primary">
          {t("home.item.checkDevices")}
        </Link>
      );
      break;
    case "pairing_mismatch":
      what = t("pairing.mismatchTitle");
      why = item.devices
        .map((d) =>
          t("pairing.mismatchBody", {
            agent: item.agent.label,
            date: formatListTimestamp(d.activated_at, { locale }),
            device: deviceName(t, d),
          }),
        )
        .join(" ");
      action = (
        <Link href={agentPageLink(item.agent, item.devices[0]?.did)} className="home-btn primary">
          {t("home.item.checkDevices")}
        </Link>
      );
      break;
    case "new_device":
      what = t("deviceNotice.title", { agent: item.agent.label });
      why = t("home.item.newDeviceWhy", {
        device: item.devices.map((d) => deviceName(t, d)).join("、"),
        date: formatListTimestamp(item.devices[0]?.activated_at ?? "", { locale }),
      });
      action = (
        <button
          type="button"
          className="home-btn primary"
          disabled={busy}
          onClick={async () => {
            setBusy(true);
            try {
              const approved = await acceptNewDevices(item);
              if (approved) await queryClient.invalidateQueries({ queryKey: queryKeys.agents() });
              onDone(t("home.item.newDeviceAccepted"));
            } catch {
              onDone(t("deviceList.failed"));
            } finally {
              setBusy(false);
            }
          }}
        >
          {t("deviceNotice.mine")}
        </button>
      );
      extra = (
        <Link href={agentPageLink(item.agent, item.devices[0]?.did)} className="home-link">
          {t("home.item.notMine")}
        </Link>
      );
      break;
    case "list_undecided":
      what = t("deviceList.noticeTitle", { agent: item.agent.label });
      why = t("deviceList.noticeBody");
      action = (
        <Link href={agentPageLink(item.agent)} className="home-btn primary">
          {t("home.item.chooseDevices")}
        </Link>
      );
      break;
    case "draft": {
      const name = draftRecipientName(item.draft, t);
      what = item.draft.in_reply_to ? t("home.item.draftReply", { name }) : t("home.item.draftNew", { name });
      why = t("home.item.draftWhy");
      action = (
        <button type="button" className={open ? "home-link" : "home-btn primary"} aria-expanded={open} onClick={() => setOpen((v) => !v)}>
          {open ? t("home.item.close") : t("home.item.reviewDraft")}
        </button>
      );
      break;
    }
    case "held": {
      what = t("home.item.heldWhat", { name: party(item.message.sender_did, item.message.sender_label) });
      why = heldWhy(item.message, agents, t);
      action = (
        <button type="button" className={open ? "home-link" : "home-btn primary"} aria-expanded={open} onClick={() => setOpen((v) => !v)}>
          {open ? t("home.item.close") : t("home.item.decide")}
        </button>
      );
      break;
    }
    case "computer_stopped": {
      const ago = elapsed(item.since, Date.now());
      const stale = Date.now() - item.since >= STALE_AFTER_MS;
      what = t("stoppedNotice.title", { agent: item.agent.label });
      why = [
        deviceName(t, item.device),
        t("stoppedNotice.since", { ago: t(`agentStatus.ago.${ago.unit}`, { n: ago.value }) }),
        stale ? t("stoppedNotice.stale") : t("stoppedNotice.groupSub"),
      ].join(" · ");
      action = (
        <Link href={agentPageLink(item.agent, item.device.did)} className="home-btn primary">
          {stale ? t("home.item.remove") : t("home.item.check")}
        </Link>
      );
      break;
    }
  }

  const group = groupOf(item.kind);
  return (
    <div className="home-row" data-testid="home-attention-row" data-kind={item.kind}>
      <span className={`home-tag ${TAG_TONE[item.kind]}`}>{t(`home.group.${group}`)}</span>
      <div className="home-row-text">
        {chipAgent ? <span className="home-chip">{chipAgent.label}</span> : null}
        <span className="home-what">{what}</span>
        <div className="home-muted">{why}</div>
        {extra}
      </div>
      <div className="home-acts">
        {action}
        {onPutOff ? (
          <button type="button" className="home-link home-later" onClick={onPutOff}>
            {t("notices.later")}
          </button>
        ) : null}
      </div>
      {open && item.kind === "draft" ? <DraftReview draft={item.draft} onDone={onDone} /> : null}
      {open && item.kind === "held" ? <HeldDecision message={item.message} onDone={onDone} /> : null}
    </div>
  );
}

function heldWhy(message: MessageIndexEntry, agents: Agent[], t: (key: string, vars?: Record<string, string | number>) => string): string {
  const to = agents.find((a) => a.did === message.recipient_did || (a.dids ?? []).includes(message.recipient_did));
  const reason =
    message.ai_category === "spam_denylist" || message.ai_category === "spam_burst"
      ? t(`pending.categoryName.${message.ai_category}`)
      : t("home.item.heldLowTrust");
  return [t("home.item.heldWhy"), reason, to ? t("home.item.heldTo", { agent: to.label }) : null].filter(Boolean).join(" · ");
}

/** The old 「確認が必要」 actions: let it in, throw it away, or block the sender. */
function HeldDecision({ message, onDone }: { message: MessageIndexEntry; onDone: (text: string) => void }) {
  const { t } = useTranslation();
  const updateFlags = useUpdateMessageFlagsMutation();
  const [blocking, setBlocking] = useState(false);
  const [blockStatus, setBlockStatus] = useState<BlockStatus | null>(null);
  const [failed, setFailed] = useState<string | null>(null);

  const move = async (folder: "inbox" | "trash") => {
    setFailed(null);
    try {
      await updateFlags.mutateAsync({ id: message.id, folder });
      onDone(folder === "inbox" ? t("pending.approved") : t("pending.rejected"));
    } catch {
      setFailed(folder === "inbox" ? t("pending.approveFailed") : t("pending.rejectFailed"));
    }
  };

  return (
    <div className="home-expand" data-testid="pending-row">
      <div className="home-muted">{t("pending.subjectHidden")}</div>
      <div className="home-acts">
        <button type="button" className="home-btn primary" onClick={() => void move("inbox")} disabled={updateFlags.isPending}>
          {t("pending.approve")}
        </button>
        <button type="button" className="home-btn" onClick={() => void move("trash")} disabled={updateFlags.isPending}>
          {t("pending.reject")}
        </button>
        <button
          type="button"
          className="home-btn"
          aria-expanded={blocking}
          onClick={() => {
            setBlockStatus(null);
            setBlocking((v) => !v);
          }}
        >
          {t("pending.block")}
        </button>
      </div>
      {blocking ? <BlockSenderPanel messageId={message.id} onClose={() => setBlocking(false)} onResult={setBlockStatus} /> : null}
      {blockStatus ? (
        <p role="status" className="home-note" style={{ margin: 0, color: blockStatus.kind === "error" ? "var(--danger)" : undefined }}>
          {blockStatus.text}
        </p>
      ) : null}
      {failed ? (
        <p role="status" className="home-note" style={{ margin: 0, color: "var(--danger)" }}>
          {failed}
        </p>
      ) : null}
    </div>
  );
}
