"use client";

// AI の操作履歴 (docs/35 step 4): one plain sentence per event, with the
// raw fields kept in a 「詳細」 disclosure for those who need them.

import { Suspense, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import { AppShell } from "../../_components/AppShell";
import { useAgentsQuery, useAuditLogQuery, useContactsQuery } from "../../../lib/api/hooks";
import type { Agent, AuditLogEntry, AuditLogQuery } from "../../../lib/api/types";
import { formatPartyLabel, indexContactsByDid, resolveParticipantLabel } from "../../../lib/api/labels";
import { formatListTimestamp } from "../../../lib/format/messageTime";
import { relativeAge } from "../../../lib/inbox/conversations";
import { useTranslation } from "../../../lib/i18n";

type Kind =
  | "reply"
  | "draft"
  | "settings"
  | "connect"
  | "disconnect"
  | "stop"
  | "login"
  | "warn"
  | "file"
  | "computer";

const ICON: Record<Kind, string> = {
  reply: "💬",
  draft: "📝",
  settings: "⚙️",
  connect: "🔗",
  disconnect: "✂️",
  stop: "🛑",
  login: "🔑",
  warn: "⚠️",
  file: "📎",
  computer: "💻",
};

// Every event the API records (services/api record_audit_event and the
// bridge allow-list). Sentences and labels live in `audit.events.<name>`.
const EVENTS: Record<string, { kind: Kind; critical?: boolean }> = {
  auto_reply_sent: { kind: "reply" },
  auto_reply_evaluated: { kind: "settings" },
  auto_reply_skipped_incoming_is_auto_reply: { kind: "reply" },
  auto_reply_policy_created: { kind: "settings" },
  auto_reply_policy_updated: { kind: "settings" },
  auto_reply_policy_deleted: { kind: "settings" },
  agent_draft_created: { kind: "draft" },
  agent_draft_sent: { kind: "reply" },
  agent_draft_discarded: { kind: "draft" },
  agent_message_sent: { kind: "reply" },
  oauth_grant_created: { kind: "connect" },
  oauth_grant_revoked: { kind: "disconnect" },
  cloud_access_enabled: { kind: "connect" },
  cloud_access_disabled: { kind: "disconnect" },
  emergency_shutdown: { kind: "stop", critical: true },
  credential_activated: { kind: "connect" },
  credential_revoked: { kind: "disconnect" },
  credential_activation_failed: { kind: "warn" },
  credential_auto_revoked: { kind: "warn", critical: true },
  credential_compromised: { kind: "warn", critical: true },
  refresh_reuse_detected: { kind: "warn", critical: true },
  key_rotation_started: { kind: "login" },
  token_issued: { kind: "login" },
  token_refreshed: { kind: "login" },
  token_revoked: { kind: "login" },
  attachment_upload_intent_created: { kind: "file" },
  attachment_upload_completed: { kind: "file" },
  attachment_attached_to_message: { kind: "file" },
  attachment_download_url_issued: { kind: "file" },
  attachment_deleted: { kind: "file" },
  attachment_purged: { kind: "file" },
  attachment_upload_abandoned: { kind: "file" },
  attachment_upload_rejected_rate_limit: { kind: "warn" },
  attachment_quarantined: { kind: "warn" },
  bridged_decrypt: { kind: "computer" },
  bridged_status: { kind: "computer" },
  bridged_pair_requested: { kind: "computer" },
  bridged_pair_succeeded: { kind: "computer" },
  bridged_pair_failed: { kind: "warn" },
  bridged_pair_revoked: { kind: "computer" },
};

// Quick filters: the API matches these as an event-name prefix.
const PRESETS: { prefix: string; labelKey: string }[] = [
  { prefix: "auto_reply_", labelKey: "audit.presetAutoReply" },
  { prefix: "agent_draft_", labelKey: "audit.presetDrafts" },
  { prefix: "attachment_", labelKey: "audit.presetFiles" },
  { prefix: "bridged_", labelKey: "audit.presetComputer" },
];

function str(value: unknown): string {
  return typeof value === "string" ? value : "";
}

export default function AuditLogPage() {
  return (
    <Suspense fallback={null}>
      <AuditLogPageInner />
    </Suspense>
  );
}

function AuditLogPageInner() {
  const { t, locale } = useTranslation();
  // Deep-link support: `?event=...` (and `?aid=...`) on the URL
  // pre-populates the filters. Used by the per-agent auto-reply
  // visibility panel link from /settings/agents. Read once on mount
  // — subsequent navigation goes through the in-page controls.
  const searchParams = useSearchParams();
  const [eventFilter, setEventFilter] = useState<string>(searchParams?.get("event") ?? "");
  const [aidFilter, setAidFilter] = useState<string>(searchParams?.get("aid") ?? "");
  // A prefix preset; a specific event takes precedence and clears it.
  const [presetPrefix, setPresetPrefix] = useState<string | null>(null);
  const [page, setPage] = useState(0);
  const pageSize = 30;

  const query: AuditLogQuery = {
    limit: pageSize,
    offset: page * pageSize,
    ...(eventFilter ? { event: eventFilter } : {}),
    ...(aidFilter ? { aid: aidFilter } : {}),
    ...(presetPrefix && !eventFilter ? { event_prefix: presetPrefix } : {}),
  };

  const auditQuery = useAuditLogQuery(query);
  const agentsQuery = useAgentsQuery();
  const contactsQuery = useContactsQuery();
  const agents = useMemo<Agent[]>(() => agentsQuery.data?.agents ?? [], [agentsQuery.data]);
  const contactsByDid = useMemo(
    () => indexContactsByDid(contactsQuery.data?.contacts),
    [contactsQuery.data],
  );
  const events = auditQuery.data?.events ?? [];
  const total = auditQuery.data?.total ?? 0;
  const totalPages = Math.ceil(total / pageSize);

  const agentName = (aid: string | null): string =>
    agents.find((a) => a.aid === aid)?.label ?? t("audit.someAgent");

  const partyName = (did: string): string =>
    formatPartyLabel(resolveParticipantLabel(did, null, contactsByDid, agents), t);

  const sentence = (entry: AuditLogEntry): string => {
    const detail = entry.detail ?? {};
    const vars = {
      agent: agentName(entry.aid),
      who: partyName(
        str(detail.sender_did) && entry.event !== "agent_draft_created"
          ? str(detail.sender_did)
          : str(detail.recipient_did),
      ),
      client: str(detail.client_name) || t("audit.someCloudAi"),
    };
    if (!EVENTS[entry.event]) return t("audit.unknownEvent", vars);
    if (entry.event === "auto_reply_sent" && !detail.reply_message_id) {
      return t("audit.events.auto_reply_sent.textNoReply", vars);
    }
    return t(`audit.events.${entry.event}.text`, vars);
  };

  const timeText = (iso: string): string => {
    const age = relativeAge(iso);
    switch (age.kind) {
      case "now":
        return t("messages.timeNow");
      case "minutes":
        return t("messages.timeMinutes", { n: age.n });
      case "hours":
        return t("messages.timeHours", { n: age.n });
      case "yesterday":
        return t("messages.timeYesterday");
      default:
        return formatListTimestamp(iso, { locale });
    }
  };

  const fullTime = (iso: string): string =>
    new Date(iso).toLocaleString(locale === "ja" ? "ja-JP" : "en-GB");

  const pickPreset = (prefix: string | null) => {
    setPage(0);
    setPresetPrefix(prefix);
    setEventFilter("");
  };

  // The deep-linked agent may not be in the list (a removed agent).
  const aidKnown = !aidFilter || agents.some((a) => a.aid === aidFilter);

  return (
    <AppShell title={t("audit.title")} activePath="/settings/audit">
      <div className="al">
        <p className="al-intro">{t("audit.subtitle")}</p>

        <div className="dm-chips al-chips">
          <button
            type="button"
            className={"dm-chip" + (!presetPrefix && !eventFilter ? " on" : "")}
            aria-pressed={!presetPrefix && !eventFilter}
            onClick={() => pickPreset(null)}
          >
            {t("audit.presetAll")}
          </button>
          {PRESETS.map((preset) => (
            <button
              key={preset.prefix}
              type="button"
              className={"dm-chip" + (presetPrefix === preset.prefix && !eventFilter ? " on" : "")}
              aria-pressed={presetPrefix === preset.prefix && !eventFilter}
              onClick={() => pickPreset(presetPrefix === preset.prefix ? null : preset.prefix)}
            >
              {t(preset.labelKey)}
            </button>
          ))}
        </div>

        <div className="al-filters">
          <select
            className="al-select"
            value={aidFilter}
            onChange={(e) => {
              setAidFilter(e.target.value);
              setPage(0);
            }}
            aria-label={t("audit.filterAgent")}
          >
            <option value="">{t("audit.allAgents")}</option>
            {agents.map((agent) => (
              <option key={agent.aid} value={agent.aid}>
                {agent.label}
              </option>
            ))}
            {!aidKnown ? <option value={aidFilter}>{t("audit.otherAgent")}</option> : null}
          </select>
          <select
            className="al-select"
            value={eventFilter}
            onChange={(e) => {
              setEventFilter(e.target.value);
              setPage(0);
              if (e.target.value) setPresetPrefix(null);
            }}
            aria-label={t("audit.filterEvent")}
          >
            <option value="">{t("audit.allEvents")}</option>
            {Object.keys(EVENTS).map((name) => (
              <option key={name} value={name}>
                {t(`audit.events.${name}.label`)}
              </option>
            ))}
            {eventFilter && !EVENTS[eventFilter] ? (
              <option value={eventFilter}>{eventFilter}</option>
            ) : null}
          </select>
          <span className="al-count">{t("common.items", { count: total })}</span>
        </div>

        {auditQuery.isLoading ? <p className="dm-empty">{t("audit.loading")}</p> : null}
        {auditQuery.isError ? (
          <p className="dm-empty al-error" role="alert">
            {t("audit.loadFailed")}
          </p>
        ) : null}
        {!auditQuery.isLoading && !auditQuery.isError && events.length === 0 ? (
          <div className="dm-empty">
            <p className="al-empty-title">{t("audit.emptyTitle")}</p>
            <p>{t("audit.emptyDesc")}</p>
          </div>
        ) : null}

        <ol className="al-list">
          {events.map((entry) => {
            const meta = EVENTS[entry.event];
            const kind = meta?.kind ?? "settings";
            return (
              <li
                key={entry.id}
                className={"al-row" + (meta?.critical ? " critical" : "")}
                data-testid="audit-row"
              >
                <span className="al-icon" aria-hidden="true">
                  {ICON[kind]}
                </span>
                <div className="al-body">
                  <div className="al-line">
                    <p className="al-text">{sentence(entry)}</p>
                    <time className="al-time" dateTime={entry.created_at} title={fullTime(entry.created_at)}>
                      {timeText(entry.created_at)}
                    </time>
                  </div>
                  <details className="al-details">
                    <summary>{t("audit.details")}</summary>
                    <dl>
                      <dt>{t("audit.detailKind")}</dt>
                      <dd>
                        <code>{entry.event}</code>
                      </dd>
                      <dt>{t("audit.detailTime")}</dt>
                      <dd>{fullTime(entry.created_at)}</dd>
                      {entry.aid ? (
                        <>
                          <dt>{t("audit.detailAddress")}</dt>
                          <dd>
                            <code>{entry.aid}</code>
                          </dd>
                        </>
                      ) : null}
                      {entry.credential_id ? (
                        <>
                          <dt>{t("audit.detailCredential")}</dt>
                          <dd>
                            <code>{entry.credential_id}</code>
                          </dd>
                        </>
                      ) : null}
                    </dl>
                    {Object.keys(entry.detail ?? {}).length > 0 ? (
                      <pre>{JSON.stringify(entry.detail, null, 2)}</pre>
                    ) : null}
                  </details>
                </div>
              </li>
            );
          })}
        </ol>

        {totalPages > 1 ? (
          <div className="al-pager">
            <button
              type="button"
              className="dm-btn"
              disabled={page === 0}
              onClick={() => setPage((p) => Math.max(0, p - 1))}
            >
              {t("audit.prev")}
            </button>
            <span className="al-count">
              {page + 1} / {totalPages}
            </span>
            <button
              type="button"
              className="dm-btn"
              disabled={page >= totalPages - 1}
              onClick={() => setPage((p) => p + 1)}
            >
              {t("audit.next")}
            </button>
          </div>
        ) : null}
      </div>
    </AppShell>
  );
}
