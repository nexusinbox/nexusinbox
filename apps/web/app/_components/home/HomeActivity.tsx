"use client";

// 「AI が対応したこと」 on Home (docs/41 §6.3): the latest automatic replies,
// from the audit log only — what was sent, never a guess at the outcome.
// Older ones: the conversation list filtered to automatic replies.

import Link from "next/link";
import { useMemo } from "react";
import { recentAutoReplies } from "../../../lib/agents/agent-status";
import { formatPartyLabel, indexContactsByDid, resolveParticipantLabel } from "../../../lib/api/labels";
import { useAgentsQuery, useAuditLogQuery, useContactsQuery } from "../../../lib/api/hooks";
import type { Agent } from "../../../lib/api/types";
import { formatListTimestamp } from "../../../lib/format/messageTime";
import { useTranslation } from "../../../lib/i18n";
import { conversationsHref } from "../../../lib/url/conversations";

/** How many the section shows (docs/41 §6.3). */
const SHOWN = 5;

export function HomeActivity({ agents, only = null }: { agents: Agent[]; only?: Agent | null }) {
  const { t, locale } = useTranslation();
  const auditQuery = useAuditLogQuery(
    { event: "auto_reply_sent", limit: 40, ...(only ? { aid: only.aid } : {}) },
    { refetchInterval: 30_000 },
  );
  const contactsQuery = useContactsQuery();
  const agentsQuery = useAgentsQuery();
  const many = agents.length > 1 && !only;

  const labelFor = useMemo(() => {
    const contacts = indexContactsByDid(contactsQuery.data?.contacts);
    const own = new Map((agentsQuery.data?.agents ?? []).map((a) => [a.did, a.label]));
    return (did: string) => formatPartyLabel(resolveParticipantLabel(did, own.get(did) ?? null, contacts), t);
  }, [contactsQuery.data, agentsQuery.data, t]);

  const events = auditQuery.data?.events ?? [];
  const replies = recentAutoReplies(events, SHOWN);
  const agentOf = (messageId: string) => {
    const aid = events.find((e) => e.detail.message_id === messageId)?.aid;
    return agents.find((a) => a.aid === aid) ?? null;
  };

  return (
    <section className="home-section" aria-labelledby="home-activity-title" data-testid="home-activity">
      <div className="home-section-head">
        <h2 id="home-activity-title" className="home-section-title">
          {t("home.activity.title")}
        </h2>
        <Link href={conversationsHref({ filter: "auto" })} className="home-section-more">
          {t("home.activity.all")}
        </Link>
      </div>
      <div className="home-box">
        {auditQuery.isError ? (
          <div className="home-error">
            <span className="home-error-text">{t("home.activity.failed")}</span>
            <button type="button" className="home-btn" onClick={() => void auditQuery.refetch()}>
              {t("home.retry")}
            </button>
          </div>
        ) : !auditQuery.data ? (
          <div className="home-empty">{t("home.loading")}</div>
        ) : replies.length === 0 ? (
          <div className="home-empty">{t("home.activity.none")}</div>
        ) : (
          replies.map((r) => {
            const agent = many ? agentOf(r.messageId) : null;
            return (
              <Link
                key={r.messageId}
                href={conversationsHref({ with: r.senderDid, agent: agentOf(r.messageId)?.did })}
                className="home-activity-row"
                data-testid="home-activity-row"
              >
                <span>
                  {agent ? <span className="home-chip">{agent.label}</span> : null}
                  {t(`agentStatus.recent_${r.action}`, { sender: labelFor(r.senderDid) })}
                </span>
                <span className="home-time">
                  {r.at !== null ? formatListTimestamp(new Date(r.at).toISOString(), { locale }) : ""}
                </span>
              </Link>
            );
          })
        )}
      </div>
    </section>
  );
}
