"use client";

import Link from "next/link";
import { useEffect, useMemo, useState, type CSSProperties } from "react";
import { AppShell } from "../../_components/AppShell";
import { RefreshIconButton } from "../../_components/RefreshIconButton";
import { AutoReplyPolicyPanel } from "../../_components/AutoReplyPolicyPanel";
import { AgentStatusCard, AgentStatusLine, useNow } from "../../_components/AgentStatusCard";
import { CommandLine } from "../../_components/AgentSetup";
import {
  useAgentCredentialsQuery,
  useAgentsQuery,
  useAuditLogQuery,
  useCreateAgentCredentialMutation,
  useDeleteAgentMutation,
  useEmergencyShutdownMutation,
  usePurgeAgentCredentialMutation,
  useRevokeAgentCredentialMutation,
  useUpdateAgentMutation,
} from "../../../lib/api/hooks";
import { useTwoColumnResize } from "../../../lib/ui/useTwoColumnResize";
import { useTranslation } from "../../../lib/i18n";
import type { AgentCredential } from "../../../lib/api/types";
import {
  deriveAgentMode,
  type AgentMode,
} from "../../../lib/agents/derive-mode";
import { secureLoadKey } from "../../../lib/crypto/keystore";
import {
  agentDirName,
  daemonEnrollCommand,
  daemonStartCommand,
} from "../../../lib/agents/enroll-command";
import { ConnectedAIs } from "../../_components/ConnectedAIs";
import { AgentSharePanel } from "../../_components/AgentSharePanel";
import { Avatar } from "../../_components/messages/ConversationView";

// The server's limit for an agent's bio (PATCH /agents/{id}).
const BIO_MAX = 160;

type Banner = { tone: "info" | "error" | "success"; text: string } | null;
type CreatedCredentialNotice = {
  credentialId: string;
  enrollmentSecret: string;
  aid: string;
  /** ~/.nexusinbox/<dirName> holds this agent's daemon keys and settings */
  dirName: string;
};

// Agent-level mode display (docs/21 §4.5). The helper lives in
// `lib/agents/derive-mode.ts` with its own tests covering the priority
// rules.

function AgentModePanel({
  aid,
  credentials,
}: {
  aid: string;
  credentials: AgentCredential[];
}) {
  const { t } = useTranslation();

  const mode = useMemo<AgentMode>(
    () => deriveAgentMode(aid, credentials),
    [aid, credentials],
  );

  const badgeStyle: CSSProperties =
    mode === "daemon_isolated"
      ? {
          background: "rgba(66, 133, 244, 0.14)",
          color: "var(--primary-text)",
          border: "1px solid rgba(66, 133, 244, 0.28)",
        }
      : mode === "standard"
        ? {
            background: "rgba(52, 168, 83, 0.14)",
            color: "var(--ok)",
            border: "1px solid rgba(52, 168, 83, 0.28)",
          }
        : {
            background: "rgba(128, 128, 128, 0.14)",
            color: "var(--text-muted)",
            border: "1px solid rgba(128, 128, 128, 0.28)",
          };

  const label =
    mode === "daemon_isolated"
      ? t("agents.modeDaemonIsolatedName")
      : mode === "standard"
        ? t("agents.modeStandardName")
        : t("agents.modeDefaultName");
  const desc =
    mode === "daemon_isolated"
      ? t("agents.modeDaemonIsolatedDesc")
      : mode === "standard"
        ? t("agents.modeStandardDesc")
        : t("agents.modeDefaultDesc");

  return (
    <div className="panel" style={{ marginTop: 10 }}>
      <div className="row" style={{ alignItems: "center", gap: 10 }}>
        <p className="item-title" style={{ margin: 0 }}>
          {t("agents.modeLabel")}
        </p>
        <span
          style={{
            fontSize: "var(--fs-xs)",
            fontWeight: 500,
            padding: "2px 8px",
            borderRadius: 999,
            letterSpacing: 0.3,
            whiteSpace: "nowrap",
            ...badgeStyle,
          }}
        >
          {label}
        </span>
      </div>
      <p className="item-sub" style={{ marginTop: 6 }}>
        {desc}
      </p>
      <Link
        href="/help#help-modes"
        className="item-sub"
        style={{
          fontSize: "var(--fs-xs)",
          textDecoration: "underline",
          color: "var(--primary-text)",
        }}
      >
        {t("agents.modeHelpLink")} →
      </Link>
    </div>
  );
}

/**
 * Per-agent "where are this agent's keys reachable from?" panel.
 *
 * Mode (Standard / Interactive / Default) tells you what the agent is
 * configured for; this panel tells you what the *current device* can
 * actually do with it. Two rows:
 *
 *   1. Browser keystore — does THIS browser hold either the
 *      signing or X25519 private key for the agent's current did?
 *      Answered locally by `secureLoadKey()` against IndexedDB.
 *   2. AI runtime keystore — there's no server-side signal for
 *      whether a Claude Desktop / Code instance somewhere has
 *      `~/.nexusinbox/<credential>.json`. Render as an info row so
 *      the user understands the gap rather than guessing.
 *
 * Read-only display; never reveals key material — only presence.
 */
type WhereaboutsStatus = "checking" | "present" | "absent" | "info";

function WhereaboutsRow({
  icon,
  label,
  status,
  message,
}: {
  icon: string;
  label: string;
  status: WhereaboutsStatus;
  message: string;
}) {
  const indicator = (() => {
    if (status === "checking") return { color: "var(--text-muted)", text: "…" };
    if (status === "present") return { color: "var(--ok)", text: "✓" };
    if (status === "absent") return { color: "var(--text-muted)", text: "—" };
    return { color: "var(--text-muted)", text: "◯" }; // info
  })();
  return (
    <div
      className="row"
      style={{
        alignItems: "flex-start",
        gap: 10,
        padding: "8px 0",
        borderTop: "1px solid var(--line)",
      }}
    >
      <span style={{ width: 22, fontSize: "var(--fs-md)", lineHeight: 1.4 }} aria-hidden="true">
        {icon}
      </span>
      <span style={{ flex: 1, minWidth: 0 }}>
        <span style={{ fontWeight: 500, fontSize: "var(--fs-sm)" }}>{label}</span>
        <p className="item-sub" style={{ margin: "2px 0 0", fontSize: "var(--fs-xs)" }}>
          {message}
        </p>
      </span>
      <span
        style={{
          color: indicator.color,
          fontSize: "var(--fs-sm)",
          fontWeight: 600,
          minWidth: 16,
          textAlign: "right",
        }}
        aria-label={status}
      >
        {indicator.text}
      </span>
    </div>
  );
}

function AgentKeyWhereaboutsPanel({ did }: { did: string }) {
  const { t } = useTranslation();
  const [browserStatus, setBrowserStatus] = useState<WhereaboutsStatus>("checking");

  useEffect(() => {
    let cancelled = false;
    setBrowserStatus("checking");

    // Browser keystore: presence of EITHER the signing or recipient
    // (X25519) key for the agent's current did is enough to consider
    // the browser to "have" the key set. Web UI activate stores both
    // under the same did, so this should rarely split, but using OR
    // keeps the row honest for any partial-import edge case.
    (async () => {
      try {
        const [sig, enc] = await Promise.all([
          secureLoadKey(`nexusinbox:signing-key:${did}`),
          secureLoadKey(`nexusinbox:recipient-key:${did}`),
        ]);
        if (!cancelled) setBrowserStatus(sig || enc ? "present" : "absent");
      } catch {
        if (!cancelled) setBrowserStatus("absent");
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [did]);


  return (
    <div className="panel" style={{ marginTop: 10 }}>
      <p className="item-title">{t("agents.whereaboutsTitle")}</p>
      <div style={{ marginTop: 8 }}>
        <WhereaboutsRow
          icon="🌐"
          label={t("agents.whereaboutsBrowserLabel")}
          status={browserStatus}
          message={
            browserStatus === "checking"
              ? t("agents.whereaboutsBrowserChecking")
              : browserStatus === "present"
                ? t("agents.whereaboutsBrowserPresent")
                : t("agents.whereaboutsBrowserAbsent")
          }
        />
        <WhereaboutsRow
          icon="🤖"
          label={t("agents.whereaboutsRuntimeLabel")}
          status="info"
          message={t("agents.whereaboutsRuntimeHint")}
        />
      </div>
    </div>
  );
}

/**
 * Per-agent auto-reply decision history (Phase A visibility).
 *
 * The evaluator runs as a policy preview even when the master switch
 * is OFF (we saw `decision: queue_for_human / reason: master_off`
 * during today's test send). So this panel is useful in either mode:
 *
 *   - Master OFF: shows what the policy WOULD HAVE done — a preview
 *     to validate rule wiring before flipping the switch.
 *   - Master ON: shows what the policy DID — actionable feedback for
 *     tuning thresholds.
 *
 * Implementation: read-only consumer of `useAuditLogQuery` filtered
 * to `event=auto_reply_evaluated` + `aid`. We aggregate counts
 * client-side because the server doesn't expose pre-aggregated
 * stats yet — fine at Phase A scale (limit=200, so ~6 months of
 * decisions for a typical agent receiving one inbound per day).
 *
 * Out of scope: dry-run preview, rule editor, executor controls.
 */
type AutoReplyDecisionDetail = {
  agent_id?: string;
  decision?: {
    action?: string;
    reason?: string | null;
    fallback_reason?: string | null;
    matched_rule_path?: string | null;
  };
  evaluator_mode?: string;
  message_id?: string;
  policy_revision?: number | null;
  sender_did?: string;
};

type AutoReplyStatBucket =
  | "auto_accept"
  | "auto_decline"
  | "queue_for_human"
  | "other";

function bucketForAction(action?: string): AutoReplyStatBucket {
  if (action === "auto_accept") return "auto_accept";
  if (action === "auto_decline") return "auto_decline";
  if (action === "queue_for_human") return "queue_for_human";
  return "other";
}

function StatCell({
  label,
  count,
  tone,
}: {
  label: string;
  count: number;
  tone: "neutral" | "ok" | "warn" | "muted";
}) {
  const color = (() => {
    if (tone === "ok") return "var(--ok)";
    if (tone === "warn") return "var(--warn)";
    if (tone === "muted") return "var(--text-muted)";
    return "var(--text)";
  })();
  return (
    <div
      style={{
        flex: "1 1 0",
        minWidth: 0,
        padding: "8px 10px",
        borderRadius: 8,
        background: "var(--surface-alt)",
        border: "1px solid var(--line)",
      }}
    >
      <div style={{ fontSize: "var(--fs-lg)", fontWeight: 600, color, lineHeight: 1.2 }}>
        {count}
      </div>
      <div
        style={{
          fontSize: "var(--fs-xs)",
          color: "var(--text-muted)",
          marginTop: 2,
          textTransform: "lowercase",
          fontVariantNumeric: "tabular-nums",
        }}
      >
        {label}
      </div>
    </div>
  );
}

function AutoReplyVisibilityPanel({ aid }: { aid: string }) {
  const { t } = useTranslation();
  const auditQuery = useAuditLogQuery({
    event: "auto_reply_evaluated",
    aid,
    limit: 200,
  });

  const { stats, latest, total } = useMemo(() => {
    const events = auditQuery.data?.events ?? [];
    const counts: Record<AutoReplyStatBucket, number> = {
      auto_accept: 0,
      auto_decline: 0,
      queue_for_human: 0,
      other: 0,
    };
    for (const ev of events) {
      const detail = ev.detail as AutoReplyDecisionDetail | undefined;
      counts[bucketForAction(detail?.decision?.action)] += 1;
    }
    return {
      stats: counts,
      latest: events.slice(0, 5),
      total: auditQuery.data?.total ?? 0,
    };
  }, [auditQuery.data]);

  // Truncate `did:key:z6Mk...XYZW` style addresses to keep the per-row
  // metadata legible without truncating the discriminating tail.
  const truncateDid = (did: string) =>
    did.length > 24 ? `${did.slice(0, 12)}…${did.slice(-6)}` : did;

  return (
    <div className="panel" style={{ marginTop: 10 }}>
      <p className="item-title">{t("agents.autoReplyVisibilityTitle")}</p>
      <p className="item-sub" style={{ marginTop: 4, fontSize: "var(--fs-xs)" }}>
        {t("agents.autoReplyVisibilityCaption")}
      </p>

      {auditQuery.isPending ? (
        <p
          className="item-sub"
          style={{ marginTop: 10, fontSize: "var(--fs-xs)" }}
        >
          {t("agents.autoReplyVisibilityLoading")}
        </p>
      ) : auditQuery.isError ? (
        <p
          className="item-sub"
          style={{ marginTop: 10, fontSize: "var(--fs-xs)", color: "var(--danger)" }}
        >
          {t("agents.autoReplyVisibilityError")}
        </p>
      ) : total === 0 ? (
        <p
          className="item-sub"
          style={{ marginTop: 10, fontSize: "var(--fs-xs)" }}
        >
          {t("agents.autoReplyVisibilityNoData")}
        </p>
      ) : (
        <>
          <div
            style={{
              marginTop: 10,
              display: "flex",
              gap: 8,
              flexWrap: "wrap",
            }}
          >
            <StatCell
              label={t("agents.autoReplyStatTotal")}
              count={total}
              tone="neutral"
            />
            <StatCell
              label={t("agents.autoReplyStatAutoAccept")}
              count={stats.auto_accept}
              tone="ok"
            />
            <StatCell
              label={t("agents.autoReplyStatAutoDecline")}
              count={stats.auto_decline}
              tone="warn"
            />
            <StatCell
              label={t("agents.autoReplyStatQueueForHuman")}
              count={stats.queue_for_human}
              tone="muted"
            />
            {stats.other > 0 ? (
              <StatCell
                label={t("agents.autoReplyStatOther")}
                count={stats.other}
                tone="muted"
              />
            ) : null}
          </div>

          {latest.length > 0 ? (
            <div style={{ marginTop: 14 }}>
              <p className="item-sub" style={{ fontSize: "var(--fs-xs)", fontWeight: 600 }}>
                {t("agents.autoReplyVisibilityLatest", {
                  count: String(latest.length),
                })}
              </p>
              <ul
                style={{
                  margin: "6px 0 0",
                  padding: 0,
                  listStyle: "none",
                }}
              >
                {latest.map((ev) => {
                  const detail = ev.detail as
                    | AutoReplyDecisionDetail
                    | undefined;
                  const action = detail?.decision?.action ?? "other";
                  const reason = detail?.decision?.reason;
                  const sender = detail?.sender_did
                    ? truncateDid(detail.sender_did)
                    : "—";
                  const messageId = detail?.message_id;
                  return (
                    <li
                      key={ev.id}
                      style={{
                        padding: "8px 0",
                        borderTop: "1px solid var(--line)",
                        fontSize: "var(--fs-xs)",
                      }}
                    >
                      <div
                        style={{
                          display: "flex",
                          alignItems: "baseline",
                          gap: 8,
                          flexWrap: "wrap",
                        }}
                      >
                        <code
                          style={{
                            fontSize: "var(--fs-xs)",
                            fontWeight: 600,
                            padding: "1px 6px",
                            borderRadius: 4,
                            background:
                              action === "auto_accept"
                                ? "rgba(19, 115, 51, 0.12)"
                                : action === "auto_decline"
                                  ? "rgba(180, 83, 9, 0.12)"
                                  : "var(--surface-alt)",
                            color:
                              action === "auto_accept"
                                ? "var(--ok)"
                                : action === "auto_decline"
                                  ? "var(--warn)"
                                  : "var(--text)",
                          }}
                        >
                          {action}
                        </code>
                        <span
                          className="item-sub"
                          style={{
                            margin: 0,
                            fontSize: "var(--fs-xs)",
                            color: "var(--text-muted)",
                          }}
                        >
                          {new Date(ev.created_at).toLocaleString()}
                        </span>
                      </div>
                      <p
                        className="item-sub"
                        style={{ margin: "4px 0 0", fontSize: "var(--fs-xs)" }}
                      >
                        {t("agents.autoReplyDecisionFrom", { sender })}
                        {reason
                          ? ` · ${t("agents.autoReplyDecisionReason", {
                              reason,
                            })}`
                          : ""}
                        {messageId
                          ? ` · ${t("agents.autoReplyDecisionMessage", {
                              messageId: messageId.slice(0, 8),
                            })}`
                          : ""}
                      </p>
                    </li>
                  );
                })}
              </ul>
            </div>
          ) : null}

          {total > latest.length ? (
            <p
              className="item-sub"
              style={{ marginTop: 10, fontSize: "var(--fs-xs)" }}
            >
              {t("agents.autoReplyShowingLatest", {
                limit: String(latest.length),
                total: String(total),
              })}
            </p>
          ) : null}

          <Link
            href={`/settings/audit?event=auto_reply_evaluated&aid=${encodeURIComponent(aid)}`}
            className="item-sub"
            style={{
              display: "inline-block",
              marginTop: 10,
              fontSize: "var(--fs-xs)",
              textDecoration: "underline",
              color: "var(--primary-text)",
            }}
          >
            {t("agents.autoReplyVisibilityViewAll")}
          </Link>
        </>
      )}
    </div>
  );
}

export default function AgentsSettingsPage() {
  const { t } = useTranslation();
  const agentsQuery = useAgentsQuery();
  const updateAgent = useUpdateAgentMutation();
  const deleteAgent = useDeleteAgentMutation();
  const credentialsQuery = useAgentCredentialsQuery();
  const now = useNow(15_000);
  // Below the profile: the status card, or everything else.
  const [tab, setTab] = useState<"status" | "details">("status");
  // On phones the list and the profile take turns, as on the messages screen.
  const [mobileView, setMobileView] = useState<"list" | "detail">("list");
  const createCredential = useCreateAgentCredentialMutation();
  const revokeCredential = useRevokeAgentCredentialMutation();
  const purgeCredential = usePurgeAgentCredentialMutation();
  const emergencyShutdown = useEmergencyShutdownMutation();

  // Server-side grace window for `POST /agent-credentials/:id/purge`. Keep
  // in sync with CREDENTIAL_PURGE_GRACE_DAYS in services/api/src/lib.rs.
  const PURGE_GRACE_DAYS = 7;

  const [activeDid, setActiveDid] = useState<string>("");
  // /settings/agents?agent=<DID> opens that agent (from the new-device notice).
  useEffect(() => {
    const wanted = new URLSearchParams(window.location.search).get("agent");
    if (wanted) setActiveDid(wanted);
  }, []);
  const [editingLabel, setEditingLabel] = useState<string>("");
  const [editingBio, setEditingBio] = useState<string>("");
  const [credLabel, setCredLabel] = useState<string>("");
  const [createdCredential, setCreatedCredential] = useState<CreatedCredentialNotice | null>(null);
  const [isEditing, setIsEditing] = useState<boolean>(false);
  const [isSharing, setIsSharing] = useState<boolean>(false);
  const [banner, setBanner] = useState<Banner>(null);
  const [showRevoked, setShowRevoked] = useState<boolean>(false);
  // Ticking clock so the pending-activation countdown re-renders without
  // requiring user interaction. 15s is fine: the TTL is 10 minutes and
  // the display resolution is 1 minute until the last stretch.
  const [nowMs, setNowMs] = useState<number>(() => Date.now());
  useEffect(() => {
    const handle = setInterval(() => setNowMs(Date.now()), 15_000);
    return () => clearInterval(handle);
  }, []);

  const { layoutStyle, startResize } = useTwoColumnResize({
    storageKey: "nexusinbox.settings_agents.thread_width.v1",
    initialWidth: 340,
  });

  const agents = useMemo(
    () => agentsQuery.data?.agents ?? [],
    [agentsQuery.data],
  );

  const activeAgent = useMemo(() => {
    if (agents.length === 0) return null;
    if (activeDid) {
      return agents.find((agent) => agent.did === activeDid) ?? agents[0];
    }
    return agents[0];
  }, [agents, activeDid]);

  // Reset per-agent transient state whenever the selection changes so
  // nothing visibly bleeds across agents:
  //   - profile edit buffer (would clobber the new agent's name and bio)
  //   - one-shot credential notice (the credentialId / enrollmentSecret
  //     panel is bound to the agent it was created for; keeping it
  //     visible after the user switches agents is confusing and looks
  //     like the values belong to the new selection)
  useEffect(() => {
    setIsEditing(false);
    setEditingLabel(activeAgent?.label ?? "");
    setEditingBio(activeAgent?.bio ?? "");
    setCreatedCredential(null);
  }, [activeAgent?.did, activeAgent?.label, activeAgent?.bio]);
  // The 紹介する panel belongs to the agent it was opened for.
  useEffect(() => {
    setIsSharing(false);
  }, [activeAgent?.did]);

  const handleSaveProfile = async () => {
    if (!activeAgent) return;
    const label = editingLabel.trim();
    const bio = editingBio.trim();
    if (!label) {
      setBanner({ tone: "error", text: t("agents.bannerNameEmpty") });
      return;
    }
    if (label === activeAgent.label && bio === (activeAgent.bio ?? "")) {
      setIsEditing(false);
      return;
    }
    try {
      await updateAgent.mutateAsync({ id: activeAgent.id, body: { label, bio } });
      setIsEditing(false);
      setBanner({ tone: "success", text: t("agents.bannerProfileUpdated") });
    } catch {
      setBanner({ tone: "error", text: t("agents.bannerProfileFailed") });
    }
  };

  const handleToggleAutoReply = async () => {
    if (!activeAgent) return;
    try {
      await updateAgent.mutateAsync({
        id: activeAgent.id,
        body: { auto_reply: !activeAgent.auto_reply },
      });
      setBanner({
        tone: "success",
        text: activeAgent.auto_reply
          ? t("agents.bannerAutoReplyOff")
          : t("agents.bannerAutoReplyOn"),
      });
    } catch {
      setBanner({ tone: "error", text: t("agents.bannerAutoReplyFailed") });
    }
  };

  const handleDelete = async () => {
    if (!activeAgent) return;
    const confirmed = window.confirm(
      t("agents.confirmDelete", { label: activeAgent.label }),
    );
    if (!confirmed) return;
    try {
      await deleteAgent.mutateAsync(activeAgent.id);
      setActiveDid("");
      setBanner({ tone: "success", text: t("agents.bannerDeleted") });
    } catch {
      setBanner({ tone: "error", text: t("agents.bannerDeleteFailed") });
    }
  };

  const copyValue = async (value: string, successText: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setBanner({ tone: "success", text: successText });
    } catch {
      setBanner({ tone: "error", text: t("agents.bannerCopyFailed") });
    }
  };

  const bannerClass =
    banner?.tone === "error"
      ? "item-sub"
      : banner?.tone === "success"
        ? "item-sub"
        : "item-sub";

  return (
    <AppShell
      title={t("agents.title")}
      activePath="/settings/agents"
      rightAction={
        <RefreshIconButton
          onClick={() => agentsQuery.refetch()}
          label={t("agents.refresh")}
        />
      }
    >
      {/* Action bar directly below the topbar search, so the create
          affordance stays in a consistent location. */}
      <section className="agent-switcher-bar">
        <Link className="btn primary" href="/onboarding">
          {t("agents.newAgent")}
        </Link>
      </section>
      <section className={`mail-layout mobile-${mobileView}`} style={layoutStyle}>
        <aside className="thread-list">
          {agents.length === 0 ? (
            <div className="empty-state" style={{ padding: 16 }}>
              {t("agents.empty")}
            </div>
          ) : (
            agents.map((agent, index) => {
              const isActive = activeAgent
                ? activeAgent.did === agent.did
                : index === 0;
              return (
                <button
                  type="button"
                  className={"dm-row" + (isActive ? " active" : "")}
                  key={agent.id + "-" + agent.did}
                  onClick={() => {
                    setActiveDid(agent.did);
                    setMobileView("detail");
                  }}
                >
                  <Avatar did={agent.did} name={agent.label} />
                  <span className="dm-row-body">
                    <span className="dm-line1">
                      <span className="dm-name">{agent.label}</span>
                      {agent.unread_count > 0 ? (
                        <span className="dm-time">
                          {t("agents.unread", { count: agent.unread_count })}
                        </span>
                      ) : null}
                    </span>
                    <AgentStatusLine
                      aid={agent.aid}
                      credentials={credentialsQuery.data?.credentials ?? []}
                      now={now}
                    />
                  </span>
                </button>
              );
            })
          )}
        </aside>

        <div className="mail-resizer" onMouseDown={startResize} />

        <article className="reader-pane" style={{ borderRight: "none" }}>
          {activeAgent ? (
            <>
              {/* Profile (docs/35 §2 "エージェント"): cover, face, name, bio,
                  address and where it runs; the tabs below hold the rest. */}
              <header className="ap-profile">
                <button
                  type="button"
                  className="dm-icon-btn dm-back ap-back"
                  onClick={() => setMobileView("list")}
                  aria-label={t("agents.backToList")}
                >
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                    <line x1="19" y1="12" x2="5" y2="12" />
                    <polyline points="12 19 5 12 12 5" />
                  </svg>
                </button>
                <div className="ap-cover" aria-hidden="true" />
                <div className="ap-head">
                  <div className="ap-avwrap">
                    <Avatar did={activeAgent.did} name={activeAgent.label} large />
                    {isEditing ? null : (
                      <div className="ap-actions">
                        <button
                          className={"dm-btn" + (isSharing ? " on" : "")}
                          type="button"
                          aria-expanded={isSharing}
                          onClick={() => setIsSharing((open) => !open)}
                          data-testid="agent-share"
                        >
                          {t("share.button")}
                        </button>
                        <button
                          className="dm-btn"
                          type="button"
                          onClick={() => {
                            setIsEditing(true);
                            setIsSharing(false);
                            setEditingLabel(activeAgent.label);
                            setEditingBio(activeAgent.bio ?? "");
                            setBanner(null);
                          }}
                          data-testid="agent-profile-edit"
                        >
                          {t("agents.profileEdit")}
                        </button>
                      </div>
                    )}
                  </div>
                  {isEditing ? (
                    <form
                      className="ap-edit"
                      onSubmit={(event) => {
                        event.preventDefault();
                        void handleSaveProfile();
                      }}
                    >
                      <label className="ap-field">
                        <span>{t("agents.nameLabel")}</span>
                        <input
                          className="input"
                          value={editingLabel}
                          onChange={(event) => setEditingLabel(event.target.value)}
                          placeholder={t("agents.namePlaceholder")}
                          autoFocus
                        />
                      </label>
                      <label className="ap-field">
                        <span>{t("agents.bioLabel")}</span>
                        <textarea
                          className="input"
                          rows={2}
                          value={editingBio}
                          maxLength={BIO_MAX}
                          onChange={(event) => setEditingBio(event.target.value)}
                          placeholder={t("agents.bioPlaceholder")}
                        />
                        <span className="ap-count">
                          {editingBio.length}/{BIO_MAX}
                        </span>
                      </label>
                      <div className="dm-btns">
                        <button
                          className="dm-btn accent"
                          type="submit"
                          disabled={updateAgent.isPending}
                        >
                          {t("agents.save")}
                        </button>
                        <button
                          className="dm-btn"
                          type="button"
                          onClick={() => {
                            setIsEditing(false);
                            setEditingLabel(activeAgent.label);
                            setEditingBio(activeAgent.bio ?? "");
                          }}
                          disabled={updateAgent.isPending}
                        >
                          {t("agents.cancel")}
                        </button>
                      </div>
                    </form>
                  ) : (
                    <>
                      <h2 className="ap-name">{activeAgent.label}</h2>
                      {activeAgent.bio ? (
                        <p className="ap-bio">{activeAgent.bio}</p>
                      ) : (
                        <p className="ap-bio muted">{t("agents.bioEmpty")}</p>
                      )}
                      {isSharing ? <AgentSharePanel agent={activeAgent} /> : null}
                    </>
                  )}
                  <div data-testid="agent-address">
                    <CommandLine command={activeAgent.aid || activeAgent.did} testId="agent-address-value" />
                    <p className="ap-hint">{t("agents.addressDesc")}</p>
                  </div>
                  <div className="ap-facts">
                    <AgentStatusLine
                      aid={activeAgent.aid}
                      credentials={credentialsQuery.data?.credentials ?? []}
                      now={now}
                    />
                    <span>{t("agents.unread", { count: activeAgent.unread_count })}</span>
                    <Link
                      className="dm-link"
                      href={`/?agent=${encodeURIComponent(activeAgent.did)}`}
                    >
                      {t("agents.openInbox")}
                    </Link>
                  </div>
                </div>
                <div className="ap-tabs" role="tablist" aria-label={t("agents.tabsLabel")}>
                  <button
                    type="button"
                    role="tab"
                    aria-selected={tab === "status"}
                    className={tab === "status" ? "on" : ""}
                    onClick={() => setTab("status")}
                  >
                    {t("agents.tabStatus")}
                  </button>
                  <button
                    type="button"
                    role="tab"
                    aria-selected={tab === "details"}
                    className={tab === "details" ? "on" : ""}
                    onClick={() => setTab("details")}
                    data-testid="agent-details-tab"
                  >
                    {t("agents.tabDetails")}
                  </button>
                </div>
              </header>

              <div className="reader-body ap-body">
                {banner ? (
                  <p className={bannerClass} style={{ marginBottom: 12 }}>
                    {banner.text}
                  </p>
                ) : null}

                {tab === "status" ? <AgentStatusCard agent={activeAgent} /> : null}

                {tab === "details" ? (
                <div data-testid="agent-details">
                {activeAgent.aid ? <ConnectedAIs aid={activeAgent.aid} /> : null}

                <div className="panel" style={{ marginTop: 10 }}>
                  <p className="item-title">{t("agents.overviewTitle")}</p>
                  <p className="item-sub">
                    {[
                      t("agents.createdAt", { date: new Date(activeAgent.created_at).toLocaleDateString() }),
                      t("agents.unreadCount", { count: activeAgent.unread_count }),
                      activeAgent.is_active ? t("agents.statusActive") : t("agents.statusStopped"),
                    ].join(" · ")}
                  </p>
                  {/* The address people use is at the top of the page; these are for developers. */}
                  <details className="item-sub" style={{ marginTop: 6 }}>
                    <summary style={{ cursor: "pointer", fontWeight: 700 }}>{t("agents.idsTitle")}</summary>
                    {activeAgent.aid ? (
                      <p style={{ margin: "6px 0 0", wordBreak: "break-all" }}>
                        {t("agents.agentId", { aid: activeAgent.aid })}
                      </p>
                    ) : null}
                    <p style={{ margin: "4px 0 0", wordBreak: "break-all" }}>
                      {t("agents.currentDid", { did: activeAgent.did })}
                    </p>
                    <p style={{ margin: "4px 0 0" }}>{t("agents.idsHelp")}</p>
                    <div className="row" style={{ gap: 8, marginTop: 6, flexWrap: "wrap" }}>
                      {activeAgent.aid ? (
                        <button
                          className="btn"
                          type="button"
                          onClick={() => copyValue(activeAgent.aid, t("agents.bannerAidCopied"))}
                        >
                          {t("agents.copyAgentId")}
                        </button>
                      ) : null}
                      <button
                        className="btn"
                        type="button"
                        onClick={() => copyValue(activeAgent.did, t("agents.bannerDidCopied"))}
                      >
                        {t("agents.copyDid")}
                      </button>
                    </div>
                  </details>
                </div>

                <AgentModePanel
                  aid={activeAgent.aid}
                  credentials={credentialsQuery.data?.credentials ?? []}
                />

                {/* Per-device "where are this agent's keys reachable
                    from?" panel — pairs with the Mode badge above by
                    answering the orthogonal question of what THIS
                    device can do with the agent right now. Renders
                    only when we know a current did to ask about. */}
                {activeAgent.did ? (
                  <AgentKeyWhereaboutsPanel did={activeAgent.did} />
                ) : null}

                <div className="panel" style={{ marginTop: 10 }}>
                  <div
                    className="row"
                    style={{
                      justifyContent: "space-between",
                      alignItems: "center",
                      gap: 12,
                    }}
                  >
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <p className="item-title">{t("agents.autoReplyTitle")}</p>
                      <p className="item-sub" style={{ marginTop: 4 }}>
                        {t("agents.autoReplyDesc")}
                      </p>
                      <p className="item-sub" style={{ marginTop: 4 }}>
                        {t("agents.approvalQueueNote")}
                      </p>
                    </div>
                    <button
                      className="btn"
                      type="button"
                      onClick={handleToggleAutoReply}
                      disabled={updateAgent.isPending}
                    >
                      {activeAgent.auto_reply ? t("agents.autoReplyDisableBtn") : t("agents.autoReplyEnableBtn")}
                    </button>
                  </div>
                </div>

                <AutoReplyPolicyPanel
                  agentId={activeAgent.id}
                  masterEnabled={activeAgent.auto_reply}
                />

                <AutoReplyVisibilityPanel aid={activeAgent.aid} />

                <div className="panel" style={{ marginTop: 10 }}>
                  <p className="item-title">{t("agents.credentialsTitle")}</p>
                  <p className="item-sub" style={{ marginTop: 4 }}>
                    {t("agents.credentialsDesc")}
                  </p>

                  {(() => {
                    const allForAgent = (credentialsQuery.data?.credentials ?? []).filter(
                      (c) => c.aid === activeAgent.aid,
                    );
                    const isLive = (s: string) => s === "active" || s === "pending";
                    // A connect code that expired unused needs nothing done:
                    // leave it out (docs/agent_details_tab_mock.html §1).
                    const expiredCode = (c: (typeof allForAgent)[number]) =>
                      c.status === "pending" &&
                      !!c.enrollment_expires_at &&
                      Date.parse(c.enrollment_expires_at) <= nowMs;
                    const liveCreds = allForAgent.filter((c) => isLive(c.status) && !expiredCode(c));
                    const deadCreds = allForAgent.filter((c) => !isLive(c.status));
                    const visibleCreds = showRevoked
                      ? [...liveCreds, ...deadCreds]
                      : liveCreds;

                    // Render the pending status line with a countdown derived
                    // from enrollment_expires_at. All TTL arithmetic happens
                    // client-side off the server-provided timestamp so the
                    // display stays correct even if the TTL policy changes.
                    const renderPendingStatus = (expiresAtIso: string | null | undefined) => {
                      if (!expiresAtIso) return t("agents.credStatusPending");
                      const expMs = Date.parse(expiresAtIso);
                      if (Number.isNaN(expMs)) return t("agents.credStatusPending");
                      const deltaMs = expMs - nowMs;
                      if (deltaMs <= 0) return t("agents.credExpired");
                      if (deltaMs < 60_000) {
                        return t("agents.credExpiresSoon", {
                          seconds: Math.max(1, Math.ceil(deltaMs / 1000)),
                        });
                      }
                      return t("agents.credExpiresIn", {
                        minutes: Math.ceil(deltaMs / 60_000),
                      });
                    };

                    return (
                      <>
                        {visibleCreds.length > 0 ? (
                          <div style={{ marginTop: 8 }}>
                            {visibleCreds.map((cred) => {
                              const isDead = !isLive(cred.status);
                              return (
                                <div
                                  key={cred.credential_id}
                                  className="row"
                                  style={{
                                    justifyContent: "space-between",
                                    alignItems: "center",
                                    gap: 8,
                                    padding: "6px 0",
                                    borderBottom: "1px solid var(--border)",
                                    opacity: isDead ? 0.55 : 1,
                                  }}
                                >
                                  <div style={{ minWidth: 0 }}>
                                    <p className="card-title" style={{ margin: 0, fontSize: "var(--fs-sm)" }}>
                                      {cred.label}
                                    </p>
                                    <p className="card-sub" style={{ margin: 0, fontSize: "var(--fs-xs)" }}>
                                      {cred.status === "active"
                                        ? t("agents.credStatusActive")
                                        : cred.status === "pending"
                                          ? renderPendingStatus(cred.enrollment_expires_at)
                                          : cred.status === "revoked"
                                            ? t("agents.credStatusRevoked")
                                            : t("agents.credStatusCompromised")}
                                      {cred.last_used_at
                                        ? t("agents.credLastUsed", { date: new Date(cred.last_used_at).toLocaleDateString() })
                                        : ""}
                                    </p>
                                  </div>
                                  <div className="row" style={{ gap: 6, flexShrink: 0 }}>
                                    {!isDead ? (
                                      <button
                                        className="btn"
                                        type="button"
                                        style={{
                                          fontSize: "var(--fs-xs)",
                                          borderColor: "rgba(220, 38, 38, 0.4)",
                                          color: "var(--danger)",
                                        }}
                                        disabled={revokeCredential.isPending}
                                        onClick={async () => {
                                          if (!window.confirm(t("agents.confirmRevoke")))
                                            return;
                                          try {
                                            await revokeCredential.mutateAsync(cred.credential_id);
                                            setBanner({ tone: "success", text: t("agents.bannerCredRevoked") });
                                          } catch {
                                            setBanner({ tone: "error", text: t("agents.bannerCredRevokeFailed") });
                                          }
                                        }}
                                      >
                                        {t("agents.credRevoke")}
                                      </button>
                                    ) : null}
                                    {cred.status === "revoked"
                                      ? (() => {
                                          // Compute grace from the server-provided revoked_at,
                                          // not from created_at, so the server's eligibility
                                          // check is what actually gates the button.
                                          const revokedMs = cred.revoked_at
                                            ? Date.parse(cred.revoked_at)
                                            : NaN;
                                          if (Number.isNaN(revokedMs)) return null;
                                          const graceMs =
                                            PURGE_GRACE_DAYS * 24 * 60 * 60 * 1000;
                                          const elapsedMs = nowMs - revokedMs;
                                          const remainingMs = graceMs - elapsedMs;
                                          if (remainingMs > 0) {
                                            return (
                                              <span
                                                className="item-sub"
                                                style={{ fontSize: "var(--fs-xs)", opacity: 0.8 }}
                                              >
                                                {t("agents.credPurgePendingGrace", {
                                                  days: Math.ceil(remainingMs / (24 * 60 * 60 * 1000)),
                                                })}
                                              </span>
                                            );
                                          }
                                          return (
                                            <button
                                              className="btn"
                                              type="button"
                                              style={{
                                                fontSize: "var(--fs-xs)",
                                                borderColor: "rgba(220, 38, 38, 0.7)",
                                                color: "var(--danger)",
                                              }}
                                              disabled={purgeCredential.isPending}
                                              onClick={async () => {
                                                if (!window.confirm(t("agents.credPurgeConfirm"))) return;
                                                try {
                                                  await purgeCredential.mutateAsync(
                                                    cred.credential_id,
                                                  );
                                                  setBanner({
                                                    tone: "success",
                                                    text: t("agents.credPurgeSuccess"),
                                                  });
                                                } catch (err) {
                                                  const isGrace =
                                                    err && typeof err === "object" && "status" in err
                                                      ? (err as { status?: number }).status === 409
                                                      : false;
                                                  setBanner({
                                                    tone: "error",
                                                    text: isGrace
                                                      ? t("agents.credPurgeGraceError")
                                                      : t("agents.credPurgeFailed"),
                                                  });
                                                }
                                              }}
                                            >
                                              {t("agents.credPurge")}
                                            </button>
                                          );
                                        })()
                                      : null}
                                  </div>
                                </div>
                              );
                            })}
                          </div>
                        ) : (
                          <p className="item-sub" style={{ marginTop: 8 }}>
                            {allForAgent.length === 0
                              ? t("agents.credEmpty")
                              : t("agents.credEmptyLive")}
                          </p>
                        )}
                        {deadCreds.length > 0 ? (
                          <div style={{ marginTop: 6 }}>
                            <button
                              type="button"
                              className="btn"
                              style={{ fontSize: "var(--fs-xs)" }}
                              onClick={() => setShowRevoked((prev) => !prev)}
                            >
                              {showRevoked
                                ? t("agents.credHideRevoked")
                                : t("agents.credShowRevoked", { count: deadCreds.length })}
                            </button>
                          </div>
                        ) : null}
                      </>
                    );
                  })()}

                  {/* Registering by hand is for people running the Signer
                      Daemon themselves; everyone else connects from the
                      status tab (docs/agent_details_tab_mock.html §1). */}
                  <details
                    className="item-sub"
                    style={{ marginTop: 10 }}
                    open={createdCredential ? true : undefined}
                  >
                    <summary style={{ cursor: "pointer", fontWeight: 700 }}>{t("agents.credManualTitle")}</summary>
                    <p style={{ margin: "6px 0 0" }}>{t("agents.credManualDesc")}</p>
                    {(credentialsQuery.data?.credentials ?? [])
                      .filter((c) => c.aid === activeAgent.aid && c.status === "active")
                      .map((c) => (
                        <div key={c.credential_id} className="row" style={{ gap: 8, marginTop: 6, flexWrap: "wrap" }}>
                          <span style={{ wordBreak: "break-all" }}>
                            {t("agents.credIdLine", { label: c.label, id: c.credential_id })}
                          </span>
                          <button
                            className="btn"
                            type="button"
                            onClick={() => copyValue(c.credential_id, t("agents.bannerCredIdCopied"))}
                          >
                            {t("agents.copy")}
                          </button>
                        </div>
                      ))}
                  <div style={{ marginTop: 10 }}>
                    <input
                      className="input"
                      value={credLabel}
                      onChange={(e) => setCredLabel(e.target.value)}
                      placeholder={t("agents.credNewPlaceholder")}
                      style={{ fontSize: "var(--fs-sm)" }}
                    />
                    <div className="row" style={{ marginTop: 6, gap: 8 }}>
                      <button
                        className="btn primary"
                        type="button"
                        disabled={createCredential.isPending}
                        onClick={async () => {
                          const label = credLabel.trim();
                          if (!label) {
                            setBanner({ tone: "error", text: t("agents.bannerCredNameEmpty") });
                            return;
                          }
                          try {
                            const result = await createCredential.mutateAsync({
                              agent_id: activeAgent.id,
                              label,
                            });
                            setCredLabel("");
                            setCreatedCredential(
                              result.enrollment_secret
                                ? {
                                    credentialId: result.credential_id,
                                    enrollmentSecret: result.enrollment_secret,
                                    aid: result.aid,
                                    dirName: agentDirName(activeAgent.label, result.aid),
                                  }
                                : null,
                            );
                            setBanner({
                              tone: "success",
                              text: t("agents.bannerCredCreated"),
                            });
                          } catch {
                            setBanner({ tone: "error", text: t("agents.bannerCredCreateFailed") });
                          }
                        }}
                      >
                        {createCredential.isPending ? t("agents.credCreating") : t("agents.credNewBtn")}
                      </button>
                    </div>
                  </div>

                  {createdCredential ? (
                    <div
                      style={{
                        marginTop: 10,
                        padding: 10,
                        background: "rgba(255, 200, 0, 0.1)",
                        border: "1px solid rgba(255, 200, 0, 0.3)",
                        borderRadius: 6,
                      }}
                    >
                      <p className="item-title" style={{ fontSize: "var(--fs-xs)" }}>
                        {t("agents.enrollmentTitle")}
                      </p>
                      <div style={{ marginTop: 6 }}>
                        <p className="item-sub" style={{ fontSize: "var(--fs-xs)" }}>
                          {t("agents.enrollmentAid", { aid: createdCredential.aid })}
                        </p>
                        <p className="item-sub" style={{ fontSize: "var(--fs-xs)", marginTop: 6 }}>
                          {t("agents.enrollmentCredentialId")}
                        </p>
                        <code
                          style={{
                            display: "block",
                            wordBreak: "break-all",
                            fontSize: "var(--fs-xs)",
                            marginTop: 4,
                            userSelect: "all",
                          }}
                        >
                          {createdCredential.credentialId}
                        </code>
                        <button
                          className="btn"
                          type="button"
                          style={{ marginTop: 6, fontSize: "var(--fs-xs)" }}
                          onClick={() =>
                            copyValue(
                              createdCredential.credentialId,
                              t("agents.bannerCredIdCopied"),
                            )
                          }
                        >
                          {t("agents.copyCredentialId")}
                        </button>
                        <p className="item-sub" style={{ fontSize: "var(--fs-xs)", marginTop: 10 }}>
                          {t("agents.enrollmentSecretLabel")}
                        </p>
                        <code
                          style={{
                            display: "block",
                            wordBreak: "break-all",
                            fontSize: "var(--fs-xs)",
                            marginTop: 4,
                            userSelect: "all",
                          }}
                        >
                          {createdCredential.enrollmentSecret}
                        </code>
                        <button
                          className="btn"
                          type="button"
                          style={{ marginTop: 6, fontSize: "var(--fs-xs)" }}
                          onClick={() =>
                            copyValue(
                              createdCredential.enrollmentSecret,
                              t("agents.bannerEnrollmentSecretCopied"),
                            )
                          }
                        >
                          {t("agents.copyEnrollmentSecret")}
                        </button>
                        <p className="item-sub" style={{ fontSize: "var(--fs-xs)", marginTop: 10 }}>
                          {t("agents.enrollmentCommandLabel")}
                        </p>
                        <code
                          style={{
                            display: "block",
                            whiteSpace: "pre-wrap",
                            wordBreak: "break-all",
                            fontSize: "var(--fs-xs)",
                            marginTop: 4,
                            userSelect: "all",
                          }}
                        >
                          {daemonEnrollCommand(createdCredential.credentialId, createdCredential.dirName)}
                        </code>
                        <button
                          className="btn"
                          type="button"
                          style={{ marginTop: 6, fontSize: "var(--fs-xs)" }}
                          onClick={() =>
                            copyValue(
                              daemonEnrollCommand(createdCredential.credentialId, createdCredential.dirName),
                              t("agents.bannerEnrollCommandCopied"),
                            )
                          }
                        >
                          {t("agents.copyEnrollCommand")}
                        </button>
                        <p className="item-sub" style={{ fontSize: "var(--fs-xs)", marginTop: 10 }}>
                          {t("agents.enrollmentStartLabel")}
                        </p>
                        <code
                          style={{
                            display: "block",
                            whiteSpace: "pre-wrap",
                            wordBreak: "break-all",
                            fontSize: "var(--fs-xs)",
                            marginTop: 4,
                            userSelect: "all",
                          }}
                        >
                          {daemonStartCommand(createdCredential.dirName)}
                        </code>
                      </div>
                      <button
                        className="btn"
                        type="button"
                        style={{ marginTop: 8, fontSize: "var(--fs-xs)" }}
                        onClick={() => setCreatedCredential(null)}
                      >
                        {t("agents.enrollmentClose")}
                      </button>
                    </div>
                  ) : null}
                  </details>
                </div>
                </div>
                ) : null}

                <div className="panel ap-danger">
                  <p className="item-title">{t("agents.dangerTitle")}</p>

                  <div style={{ marginTop: 8 }}>
                    <p className="item-sub">
                      {t("agents.emergencyDesc")}
                    </p>
                    <div className="row" style={{ marginTop: 6 }}>
                      <button
                        className="btn"
                        type="button"
                        disabled={emergencyShutdown.isPending}
                        style={{
                          borderColor: "rgba(220, 38, 38, 0.4)",
                          color: "var(--danger)",
                          fontWeight: 600,
                        }}
                        onClick={async () => {
                          if (
                            !window.confirm(t("agents.confirmEmergency"))
                          )
                            return;
                          try {
                            const result = await emergencyShutdown.mutateAsync(activeAgent.id);
                            setBanner({
                              tone: "success",
                              text: t("agents.emergencyDone", { creds: result.credentials_revoked, tokens: result.tokens_revoked, apps: result.ai_apps_disconnected ?? 0 }),
                            });
                          } catch {
                            setBanner({ tone: "error", text: t("agents.emergencyFailed") });
                          }
                        }}
                      >
                        {emergencyShutdown.isPending ? t("agents.emergencyRunning") : t("agents.emergencyBtn")}
                      </button>
                    </div>
                  </div>

                  <div style={{ marginTop: 12, paddingTop: 10, borderTop: "1px solid var(--border)" }}>
                    <p className="item-sub">
                      {t("agents.deleteDesc")}
                    </p>
                    <div className="row" style={{ marginTop: 6 }}>
                      <button
                        className="btn"
                        type="button"
                        onClick={handleDelete}
                        disabled={deleteAgent.isPending}
                        style={{
                          borderColor: "rgba(220, 38, 38, 0.4)",
                          color: "var(--danger)",
                        }}
                      >
                        {deleteAgent.isPending ? t("agents.deleting") : t("agents.deleteBtn")}
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            </>
          ) : (
            <div className="empty-state">
              {t("agents.emptyReader")}
            </div>
          )}
        </article>
      </section>
    </AppShell>
  );
}
